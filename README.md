# terraformizer

Outil Python qui repère les ressources créées **hors Terraform** dans un projet
et propose une migration : fichiers HCL par fournisseur, rapports et script
`terraform import`. L'analyse est statique : aucun script source ni appel cloud
n'est exécuté. Python **3.10 ou supérieur** et Terraform **1.5 ou supérieur**
(pour utiliser les fichiers générés).

## Installation

Depuis ce dépôt :

```bash
python -m pip install -e .
terraformizer --help
```

Dépendances d'exécution : `pyyaml`, `rich`.

## Tests

Installer les dépendances de développement et lancer la suite :

```bash
python -m pip install -e ".[dev]"
pytest
pytest --update-snapshots
ruff check .
ruff format --check .
```

La suite comprend des snapshots déterministes, des propriétés Hypothesis et
un test d'intégration Terraform. `pytest --update-snapshots` régénère les fichiers
dans `tests/snapshots/` : relire chaque différence avant de les committer.
Le test Terraform est ignoré lorsque `terraform` est absent du `PATH`; il exécute
`terraform fmt -check -diff`, `terraform init` et `terraform validate` pour chaque
fournisseur des fixtures. La CI l'exécute dans un job séparé avec Terraform 1.9.x.
La CI exécute aussi les tests et Ruff avec Python 3.10, 3.11 et 3.12.

## Usage

```bash
terraformizer ./mon-projet -o ./terraformized --report both
terraformizer ./mon-projet --only bash_aws python_boto3 --min-confidence 0.5
terraformizer ./mon-projet --dry-run --fail-on-findings
terraformizer ./mon-projet -o ./terraformized --fmt
```

| Option | Effet |
| --- | --- |
| `-o`, `--out` | Dossier de sortie, `terraformized` par défaut |
| `--only` | Un ou plusieurs noms de détecteurs (voir architecture) |
| `--min-confidence` | Ne conserver dans les sorties que les scores ≥ ce seuil, entre 0 et 1 |
| `--report json\|md\|both` | `report.json`, `REPORT.md` ou les deux (défaut) |
| `--fmt` | Exécuter `terraform fmt -recursive` si Terraform est disponible |
| `--dry-run` | Afficher les détections, sans écrire ni formater |
| `--fail-on-findings` | Code 2 si l'analyse détecte des ressources, même filtrées |
| `--fail-on-filtered` | Code 2 si des ressources restent après `--min-confidence` |
| `--version` | Afficher la version |

Codes de retour : **0** pour une analyse réussie, **1** pour un chemin invalide
ou une erreur de lecture/écriture globale, **2** si `--fail-on-findings` trouve
des ressources avant le filtre ou si `--fail-on-filtered` trouve des ressources
après le filtre (ou pour des arguments CLI invalides).

La sortie comprend `aws.tf`, `google.tf`, `azurerm.tf` selon les fournisseurs
présents, `versions.tf`, `variables.tf`, `import.sh` exécutable et les rapports.
Les adresses dupliquées sont suffixées `_2`, `_3`, etc. Le dossier de sortie
est ignoré lors du parcours s'il est inclus dans le projet.

Exemple : `aws s3 mb s3://my-bucket-prod` produit :

```hcl
# Source : deploy.sh:7 (confiance 100%)
# Origine : aws s3 mb s3://my-bucket-prod
resource "aws_s3_bucket" "my_bucket_prod" {
  bucket = "my-bucket-prod"
}
```

Le script contient alors :

```bash
terraform import 'aws_s3_bucket.my_bucket_prod' 'my-bucket-prod'
```

Pour essayer sans compte cloud :

```bash
terraformizer tests/fixtures -o /tmp/terraformizer-demo
```

## Migration : vérifier avant d'appliquer

1. Relire **tous les TODO**, les attributs, les références et les versions de providers.
2. Compléter les variables, les blocs requis et les identifiants
   `<ID_A_RENSEIGNER>` ; décommenter les imports complétés. Copier ou ajuster
   les fichiers référencés par `file(...)`, dont les chemins sont relatifs
   au dossier Terraform généré.
3. Dans le dossier généré, lancer `terraform init`.
4. Avec les bonnes identités cloud et un backend adapté, lancer `bash import.sh`.
5. Examiner `terraform plan` : aucune ressource existante ne doit être recréée
   ou supprimée involontairement.

La conversion est une **proposition**, pas une équivalence garantie. Certains
champs requis restent à compléter (NIC Azure, contexte projet Google, clés
DynamoDB, etc.). Les références CloudFormation et les images Google sont des
approximations à vérifier ; les expressions Python dynamiques deviennent
`var.<nom>` avec une note et une déclaration de variable. Les flags et propriétés
non mappés abaissent la confiance. Les types CloudFormation inconnus restent
dans le rapport sous `UNMAPPED`, sans ressource HCL. Une exception d'un détecteur
devient `ERROR` et n'interrompt pas les autres analyses.
Les modèles avec des alias YAML sont ignorés pour empêcher les expansions
exponentielles ; les tags intrinsèques CloudFormation restent pris en charge.

**Attention aux secrets** : attributs, extraits source et rapports peuvent
contenir des données sensibles déjà présentes dans le projet. Conserver la
sortie dans un emplacement privé ; ne pas la committer sans examen. Les fichiers
générés de même nom sont réécrits : utiliser un dossier dédié et neuf pour chaque
analyse, afin d'éviter les anciens fichiers de fournisseurs ou rapports.

## Architecture

- `models.py` : `Finding`, attributs HCL, provenance, confiance, notes et import.
- `scanner.py` : parcours déterministe, chemins relatifs, fichiers ≤ 2 Mo,
  lecture UTF-8 tolérante, isolation des erreurs.
- `detectors/base.py` : contrat `Detector` et identifiants `slugify`.
- `detectors/__init__.py` : registre `ALL_DETECTORS` et sélection `get_detectors`.
- `bash_aws`, `bash_gcloud`, `bash_az` : commandes CLI, continuations de lignes
  et flags. Fichiers `.sh`, `.bash`, `.zsh`, `.yml`, `.yaml`, `.mk`, `Makefile`,
  `Jenkinsfile`, `Dockerfile`.
- `python_boto3` : AST Python, littéraux, tags et valeurs dynamiques, sans importer
  ni exécuter le fichier analysé.
- `cloudformation` : YAML/JSON et tags intrinsèques chargés de manière sûre.
- `generators/hcl.py` : blocs imbriqués, listes, maps `tags`, valeurs brutes
  `{"__raw__": "var.exemple"}`, providers, variables et imports.
- `report.py`, `cli.py` : rapports Rich/JSON/Markdown et orchestration.
- `tests/fixtures` : exemples multi-cloud analysables sans SDK ni identifiants.

Le scanner ignore `.git`, `.terraform`, `node_modules`, `venv`, `.venv`,
`__pycache__`, `dist`, `build`, `.tox`, `.mypy_cache`, `*.tfstate*`, ainsi que
les fichiers `.tf`, `.tfvars`, `.hcl` et les liens symboliques. L'API Python
`scan(root, only=None, ignores=DEFAULT_IGNORES)` permet de personnaliser ces filtres.

### Ressources prises en charge

- **AWS CLI / boto3** : instances EC2, buckets S3, security groups, VPC, subnets,
  rôles/utilisateurs IAM, instances RDS, Lambda, DynamoDB, SQS, SNS, ECR,
  clusters ECS/EKS et groupes de logs ; KMS via AWS CLI.
- **gcloud** : instances, réseaux et règles firewall Compute, buckets Storage,
  clusters GKE, instances SQL, topics Pub/Sub et comptes de service.
- **Azure CLI** : groupes de ressources, VM Linux, comptes Storage, réseaux
  virtuels, clusters AKS, coffres Key Vault.
- **CloudFormation** : EC2 Instance/VPC/Subnet/SecurityGroup, S3 Bucket,
  IAM Role, Lambda Function, DynamoDB Table, SQS Queue, SNS Topic, RDS DBInstance.

## Ajouter un détecteur

1. Créer un module dans `terraformizer/detectors/` et une sous-classe de `Detector`.
2. Définir `name`, `extensions` et éventuellement `filenames`.
3. Implémenter `detect(path: Path, content: str) -> list[Finding]` :
   attribuer un provider et un type Terraform, normaliser le nom avec `slugify`,
   conserver le fichier et la ligne d'origine, annoter les limites de conversion.
4. Représenter les attributs simples par des littéraux Python, les blocs par des
   dictionnaires, les blocs répétés par des listes de dictionnaires et les
   expressions HCL par `{"__raw__": "expression"}`. `tags` reste une map.
   Ne jamais placer du contenu source non fiable directement dans une expression
   brute ; citer les chaînes et normaliser les identifiants.
5. Ajouter une instance au registre `ALL_DETECTORS`, puis des fixtures et tests
   positifs/négatifs (valeurs dynamiques, provenance, limites et imports).
6. Exécuter `pytest` et `ruff check .`.

Un détecteur doit rester statique, ne jamais appeler un cloud ou exécuter les
sources, et ne renseigner `import_id` que si le bon identifiant est connu.
