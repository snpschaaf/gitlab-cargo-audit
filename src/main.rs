mod gitlab;

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use anyhow::Context;
use petgraph::graph::NodeIndex;
use petgraph::visit::Bfs;
use rustsec::cargo_lock::dependency::Tree;
use rustsec::{Database, Report, Vulnerability};
use rustsec::Lockfile;
use serde_json;
use clap;
use clap::{Parser, Subcommand};
use gitlab::dependency_scanning_report;
use crate::gitlab::dependency_scanning_report::{DependencyScanningReport, DSRVulnerability};
use crate::gitlab::quality_report::{QualityReport, QualityReportContent};
use crate::gitlab::quality_report_location::QualityLocation;
use crate::gitlab::quality_severity::QualitySeverity;

/// Simple program to greet a person
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Path of the Cargo TOML file
    #[arg(short, long, default_value = "Cargo.toml")]
    cargo_toml: String,

    /// Path of the Cargo lock file
    #[arg(short, long, default_value = "Cargo.lock")]
    lockfile: String,

    /// Output a quality report instead of dependency_scanning report
    #[arg(short, long)]
    quality_report: bool,

    #[command(subcommand)]
    action: Mode
}

#[derive(Subcommand, Debug, Default, Clone)]
enum Mode {
    #[default]
    Auto,
    Json {
        /// Parse from json file
        audit_json: String,

        /// output file
        out: String,
    },
}


#[derive(Clone, Debug)]
struct NormalArgs {
    package_manager: String,
    report_version: String,
    scanner_id: String,
    scanner_name: String,
}

impl Default for NormalArgs {
    fn default() -> Self {
        Self {
            package_manager: "cargo".to_string(),
            report_version: "14.0.6".to_string(),
            scanner_id: "cargo_audit".to_string(),
            scanner_name: "cargo-audit".to_string(),
        }
    }
}


fn main() -> anyhow::Result<()> {

    let args: CliArgs = CliArgs::parse();

    match args.action.clone() {
        Mode::Auto => {
            normal(args.clone())
        },
        Mode::Json { audit_json, out } => {
            json(audit_json, out, args.clone())
        },
    }


}

fn json(audit_json: impl AsRef<Path>, out: impl AsRef<Path>, args: CliArgs) -> anyhow::Result<()> {
    let file = File::open(audit_json.as_ref())?;
    let report : Report = serde_json::from_reader(file).context("Parse error")?;
    let vulnerabilities = report.vulnerabilities.list;
    let opts = NormalArgs::default();

    match args.quality_report {
        true => {
            let quality_report: Vec<QualityReport> = vulnerabilities.iter()
                .map(|v| {

                    let severity = match &v.advisory.cvss {
                        None => { Default::default() }
                        Some(base) => { base.severity().into() }
                    };

                    QualityReport {
                        description: v.advisory.title.to_string(),
                        content: Some(QualityReportContent {
                            body: v.advisory.description.clone()
                        }),
                        severity: Some(severity),
                        location: QualityLocation {
                            path: "Cargo.lock".to_string(),
                            lines: Default::default()
                        },
                        ..Default::default()
                    }
                })
                .collect();

            let quality_report = match quality_report.len() {
                0 => vec![
                    QualityReport {
                        description: "No CVEs detected".to_string(),
                        content: Some(QualityReportContent {
                            body: "No CVEs found in rustsec database".to_string(),
                        }),
                        severity: Some(QualitySeverity::Info),
                        location: QualityLocation {
                            path: "Cargo.lock".to_string(),
                            lines: Default::default()
                        },
                        ..Default::default()
                    }
                ],
                _ => quality_report
            };

            let of = File::create(out.as_ref())?;
            serde_json::to_writer_pretty(of, &quality_report)?;
        }
        false => {
            let dep_scan_report = gen_dependency_scanning_report(args, opts, &vulnerabilities)?;
            let of = File::create(out.as_ref())?;
            serde_json::to_writer_pretty(of, &dep_scan_report)?;
        }
    };

    Ok(())
}

fn normal(args: CliArgs) -> anyhow::Result<()> {
    let lockfile = Lockfile::load(args.lockfile.clone()).context("failed to load lockfile")?;
    let database = Database::fetch().context("failed to fetch advisory-db")?;
    let vulnerabilities = database.vulnerabilities(&lockfile);
    let opts = NormalArgs::default();


    let report = gen_dependency_scanning_report(args, opts, &vulnerabilities)?;

    let stdout = io::stdout();
    let stdout = stdout.lock();

    serde_json::to_writer_pretty(stdout, &report)?;

    Ok(())
}

fn gen_dependency_scanning_report(args: CliArgs, opts: NormalArgs, vulnerabilities: &[Vulnerability]) -> anyhow::Result<DependencyScanningReport>  {
    let lockfile = Lockfile::load(args.lockfile.clone()).context("failed to load lockfile")?;
    let cargo_toml = load_toml(args.cargo_toml.clone()).context("failed to load Cargo.toml")?;
    let packages = discover_packages(&cargo_toml).context("failed to discover packages")?;
    let dependency_tree = lockfile.dependency_tree().context("failed to generate dependency tree")?;

    print_vulnerabilities(&vulnerabilities);
    Ok(DependencyScanningReport {
        vulnerabilities: report_vulnerabilities(&vulnerabilities, opts.clone(), args.lockfile.clone()),
        version: opts.report_version.clone(),
        dependency_files: vec![
            dependency_scanning_report::DependencyFile {
                path: args.lockfile.clone(),
                package_manager: opts.package_manager.clone(),
                dependencies: report_dependencies(&dependency_tree, &packages)
            }
        ],
    })
}

/// Load TOML file
fn load_toml(path: impl AsRef<Path>) -> io::Result<toml::Value> {
    let mut file = File::open(path.as_ref())?;

    let mut buf  = Vec::new();
    file.read_to_end(&mut buf)?;

    Ok(toml::from_slice(&buf)?)
}

/// Discover package names in package/workspace
fn discover_packages(cargo_toml: &toml::Value) -> anyhow::Result<HashSet<String>> {
    let mut packages = HashSet::new();

    if let Some(package) = cargo_toml.get("package") {
        let name = package.get("name").and_then(toml::Value::as_str)
            .ok_or(anyhow::anyhow!("missing package name"))?;

        packages.insert(name.to_string());
    } else if let Some(workspace) = cargo_toml.get("workspace") {
        let members = workspace.get("members").and_then(toml::Value::as_array)
            .map(|m| m.iter().filter_map(toml::Value::as_str).map(str::to_string))
            .ok_or(anyhow::anyhow!("missing package members"))?;

        packages.extend(members);
    } else {
        anyhow::bail!("missing package or workspace");
    }

    Ok(packages)
}

/// Print list of vulnerabilities
fn print_vulnerabilities(vulnerabilities: &[Vulnerability]) {
    if vulnerabilities.is_empty() {
        eprintln!("No vulnerabilities detected");
        return;
    }

    eprintln!("Warning: {} vulnerabilities detected", vulnerabilities.len());
    for vuln in vulnerabilities {
        eprintln!("- [{}] {} ({})", vuln.advisory.package, vuln.advisory.title, vuln.advisory.id);
        eprintln!("  See https://rustsec.org/advisories/{} for details", vuln.advisory.id);
    }
}

/// Build list of [`report::Dependency`] from a dependency tree.
fn report_dependencies(dependency_tree: &Tree, packages: &HashSet<String>) -> Vec<dependency_scanning_report::Dependency> {
    let graph = dependency_tree.graph();

    let mut dependencies = Vec::new();
    for root in dependency_tree.roots() {
        if !packages.contains(graph[root].name.as_str()) {
            continue;
        }

        let mut predecessor = vec![NodeIndex::end(); graph.node_count()];
        let mut bfs = Bfs::new(&graph, root);
        while let Some(u) = bfs.next(&graph) {
            for v in graph.neighbors(u) {
                let package = &graph[v];
                predecessor[v.index()] = u;

                let dependency_path = dependency_path(&predecessor, v);

                dependencies.push(dependency_scanning_report::Dependency {
                    package: Some(dependency_scanning_report::Package {
                        name: Some(package.name.as_str().to_owned()),
                    }),
                    version: Some(package.version.to_string()),
                    iid: Some(v.index()),
                    direct: Some(dependency_path.is_empty()),
                    dependency_path: Some(dependency_path),
                });
            }
        }
    }

    dependencies
}

/// Ancestors of the dependency, starting from a direct project dependency, and ending with an immediate parent of the dependency.
/// The dependency itself is excluded from the path. Direct dependencies have no path.
fn dependency_path(predecessor: &[NodeIndex], mut nx: NodeIndex) -> Vec<dependency_scanning_report::IID> {
    let mut path = Vec::new();
    loop {
        nx = predecessor[nx.index()];
        if predecessor[nx.index()] == NodeIndex::end() {
            // `nx` is the root
            break;
        }

        path.push(dependency_scanning_report::IID { iid: nx.index() });
    }

    path.reverse();

    path
}

/// Build list of [`report::Vulnerability`] from list of [`Vulnerability`]s.
fn report_vulnerabilities(vulnerabilities: &[Vulnerability], opts: NormalArgs, lockfile: String) -> Vec<DSRVulnerability> {
    vulnerabilities.iter().map(|vuln| {
        DSRVulnerability {
            id: Some(vuln.advisory.id.to_string()),  // FIXME: Should be a UUID
            category: String::from("dependency_scanning"),
            name: Some(vuln.advisory.title.to_string()),
            message: Some(format!("[{}] {}", vuln.advisory.package, vuln.advisory.title)),
            description: Some(vuln.advisory.description.clone()),
            cve: vuln.advisory.id.to_string(),
            severity: vuln.advisory.cvss.as_ref().map(|cvss| cvss.severity().into())
                .unwrap_or_default(),
            identifiers: vec![
                dependency_scanning_report::Identifier {
                    r#type: String::from("rustsec"),
                    name: vuln.advisory.id.to_string(),
                    value: vuln.advisory.id.to_string(),
                    url: Some(format!("https://rustsec.org/advisories/{}", vuln.advisory.id))
                }
                // TODO: Add aliases
            ],
            links: if let Some(url) = &vuln.advisory.url {
                Some(vec![
                    dependency_scanning_report::Link {
                        url: url.to_string(),
                        .. Default::default()
                    }
                ])
            } else {
                None
            },
            location: dependency_scanning_report::Location {
                file: lockfile.clone(),
                dependency: dependency_scanning_report::Dependency {
                    package: Some(dependency_scanning_report::Package {
                        name: Some(vuln.package.name.to_string()),
                    }),
                    version: Some(vuln.package.version.to_string()),
                    .. Default::default()
                },
            },
            scanner: dependency_scanning_report::Scanner {
                id: opts.scanner_id.clone(),
                name: opts.scanner_name.clone(),
            },
            ..Default::default()
        }
    }).collect()
}
