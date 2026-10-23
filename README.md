\# Vulnerability Prioritisation Tool



\## Overview



This project investigates how vulnerability severity, exploitability intelligence, and asset criticality can be combined to improve vulnerability patch prioritisation in resource-constrained organisations.



The research evaluates an integrated prioritisation approach against simpler baseline methods to determine whether combining these factors improves patch selection under limited remediation budgets.



\## Research Question



How does integrating vulnerability severity, exploitability intelligence, and asset criticality affect prioritisation effectiveness compared with single-factor approaches in resource-constrained organisations?



\## Methodology



The tool combines three main considerations:



\- \*\*Vulnerability severity:\*\* CVSS scores represent the technical severity of vulnerabilities.

\- \*\*Exploitability intelligence:\*\* EPSS estimates exploitation likelihood, while CISA Known Exploited Vulnerabilities (KEV) information identifies vulnerabilities known to have been exploited.

\- \*\*Asset criticality:\*\* Asset characteristics help represent the operational importance and potential impact of vulnerabilities on different organisational environments.



The model applies configured screening and ranking rules to prioritise vulnerabilities. Its results can be compared with baseline approaches under different remediation budgets.



\## Project Structure



```text

Vuln\_Prio\_Tool/

├── data/

│   ├── inventories/

│   │   ├── ngo\_office.csv

│   │   ├── small\_clinic.csv

│   │   ├── sme\_retail.csv

│   │   └── university\_dept.csv

│   └── processed/

│       ├── vulns.csv

│       └── vulns\_train.csv

├── results/

├── src/

├── model\_config.json

├── requirements.txt

└── README.md

```



\## Requirements



\- Python 3.10 or a compatible Python version supported by the dependencies.

\- Git.

\- Internet access when retrieving or rebuilding vulnerability data.



\## Installation



Clone the repository and enter the project directory:



```powershell

git clone https://github.com/fuzyai/Vuln\_Prio\_Tool.git

cd Vuln\_Prio\_Tool

py -m venv .venv

.\\.venv\\Scripts\\Activate.ps1

python -m pip install -r requirements.txt

```



If PowerShell prevents virtual-environment activation, you can run the Python commands using `.\\.venv\\Scripts\\python.exe` instead.



\## Running the Evaluation



Run the evaluation script using the supplied processed dataset:



```powershell

python src/evaluate\_model.py --cutoff 2024-06-30 --horizon-end 2025-06-30

```



To inspect the available evaluation options:



```powershell

python src/evaluate\_model.py --help

```



Other scripts include:



\- `src/train\_model.py` — model training.

\- `src/baselines.py` — baseline comparisons.

\- `src/montecarlo.py` — Monte Carlo analysis.

\- `src/criteria\_analysis.py` — asset-criteria analysis.

\- `src/diagnose.py` — diagnostic analysis.



Check each script's `--help` output for its supported options.



\## Rebuilding the Dataset



The ingestion script retrieves vulnerability information from external sources, including NVD, EPSS, and CISA KEV.



Example:



```powershell

python src/ingest.py --start 2023-01-01 --end 2024-12-31 --epss-date 2024-12-31

```



An NVD API key can optionally be supplied through an environment variable:



```powershell

$env:NVD\_API\_KEY = "your-key-here"

```



External vulnerability feeds may change over time. Consequently, rebuilding the dataset may not produce exactly the same data as the version used in the original experiment.



\## Data and Reproducibility



\- Processed vulnerability datasets and experiment outputs are included for analysis and reproducibility.

\- Raw downloaded data under `data/raw/` is excluded from version control.

\- `model\_config.json` records the experiment configuration and should be preserved when reproducing the original experiment.

\- Rebuilding datasets with updated external feeds may change evaluation results.



\## Limitations



The results depend on the quality and availability of vulnerability intelligence, the asset-criticality assessments, the selected configuration, and the assumptions used in evaluation. The tool supports research and decision-making; it does not replace professional security assessment or organisational patch-management policies.



\## Research Purpose



This repository supports academic research into vulnerability prioritisation for resource-constrained organisations, with an emphasis on comparing integrated risk-based approaches against simpler prioritisation strategies.



