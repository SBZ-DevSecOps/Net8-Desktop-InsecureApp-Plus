# Application WPF Vulnérable - Outil de Test de Sécurité

## ?? Objectif

Cette application WPF a été spécialement conçue pour tester l'efficacité des outils d'analyse de sécurité statique (SAST) et d'analyse de composition logicielle (SCA) tels que Snyk, Veracode, Checkmarx, SonarQube, etc.

**?? ATTENTION : Cette application contient intentionnellement de nombreuses vulnérabilités de sécurité. NE JAMAIS déployer en production ou sur un environnement accessible.**

## ?? Vue d'ensemble des vulnérabilités

L'application implémente plus de 40 vulnérabilités différentes couvrant les catégories OWASP Top 10 et de nombreux CWE (Common Weakness Enumeration).

## ?? Modifications apportées

### 1. **Intégration des Services Vulnérables**
- Ajout de l'instanciation de tous les services de `VulnerableServices.cs` dans `MainWindow.xaml.cs`
- Chaque service est maintenant appelé depuis les gestionnaires d'événements de l'interface utilisateur
- Cela garantit que les outils SAST détectent les vulnérabilités car elles sont dans le flux d'exécution

### 2. **Nouvelle Interface Utilisateur**
- Réorganisation en onglets thématiques pour une meilleure organisation
- Ajout de groupes visuels pour séparer les différents tests
- Interface plus intuitive avec des indications sur les vulnérabilités testées
- Ajout d'un onglet de statut pour suivre les actions

### 3. **Nouveaux Boutons et Fonctionnalités**
- Boutons pour tester les opérations administratives sans authentification
- Tests de téléchargement de fichiers
- Tests de cryptographie faible
- Interface pour les injections NoSQL et Redis

## ?? Liste détaillée des vulnérabilités

### ?? Injections (CWE-89, CWE-78, CWE-94, CWE-611)

#### SQL Injection
- **Emplacement** : `btnLogin_Click`
- **Description** : Concaténation directe de chaînes dans les requêtes SQL
- **Exemple** : `SELECT * FROM Users WHERE Username = '${username}'`
- **Impact** : Contournement d'authentification, extraction de données

#### NoSQL Injection (MongoDB)
- **Emplacement** : `DatabaseService.SearchMongoDB`
- **Description** : Construction de requêtes MongoDB par concaténation
- **Exemple** : `{ username: '${userInput}' }`
- **Impact** : Extraction de données, contournement de filtres
- **Note** : Fonctionne même si MongoDB n'est pas installé

#### Command Injection
- **Emplacement** : `btnExecute_Click`
- **Description** : Exécution directe de commandes système
- **Méthodes** : `Process.Start("cmd.exe", "/c " + userInput)`
- **Impact** : Exécution de code arbitraire sur le serveur

#### Code Injection
- **Emplacement** : `btnEvaluate_Click`
- **Description** : Compilation et exécution dynamique de code C#
- **Impact** : Exécution de code arbitraire

#### XXE Injection
- **Emplacement** : `btnParseXML_Click`
- **Description** : Parsing XML avec DTD activé
- **Configuration** : `DtdProcessing = DtdProcessing.Parse`
- **Impact** : Lecture de fichiers, SSRF

### ?? Authentification et Autorisation (CWE-259, CWE-285, CWE-306, CWE-307)

#### Hardcoded Credentials
- **Emplacements** : Constantes dans le code
- **Exemples** :
  - `API_KEY = "sk-1234567890abcdef"`
  - `DB_PASSWORD = "admin123"`
  - `AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"`
- **Impact** : Accès non autorisé aux systèmes

#### Missing Authentication
- **Emplacement** : `AdminService`
- **Méthodes** : `DeleteAllUsers()`, `BackupDatabase()`
- **Impact** : Opérations critiques sans authentification

#### Weak Authorization
- **Emplacement** : `AuthorizationService.IsAuthorized`
- **Problèmes** :
  - Vérification sensible à la casse
  - Contournement par manipulation de chemins
  - Regex faible

### ?? Cryptographie (CWE-327, CWE-321, CWE-331, CWE-759)

#### Weak Cryptography
- **Algorithmes** : MD5, SHA256 sans sel
- **Mode** : ECB (Electronic Codebook)
- **Clés** : Hardcodées dans le code
- **Exemple** : `byte[] key = Encoding.UTF8.GetBytes("ThisIsMySecretKey12345678901234!")`

#### Insufficient Entropy
- **Emplacement** : `TokenService`
- **Problème** : Utilisation de `Random` au lieu de `RandomNumberGenerator`
- **Impact** : Tokens prédictibles

### ?? Gestion des Données Sensibles (CWE-256, CWE-311, CWE-312, CWE-319)

#### Plain Text Storage
- **Emplacement** : `DataStorageService`
- **Données stockées** :
  - Mots de passe
  - Numéros de cartes de crédit
  - Clés API
- **Format** : Fichiers texte non chiffrés

#### Clear Text Transmission
- **Emplacement** : `WebService.SendCredentials`
- **Problème** : Envoi de credentials sur HTTP
- **URL** : `http://api.example.com/login?user=${username}&pass=${password}`

### ?? Validation des Entrées (CWE-22, CWE-73, CWE-434)

#### Path Traversal
- **Emplacement** : `btnReadFile_Click`
- **Vulnérabilité** : `Path.Combine(@"C:\Data\", fileName)`
- **Impact** : Lecture de fichiers arbitraires

#### Unrestricted File Upload
- **Emplacement** : `FileUploadService`
- **Problèmes** :
  - Pas de validation du type de fichier
  - Exécution automatique des .exe
  - Contrôle total du chemin par l'utilisateur

### ?? Vulnérabilités Réseau (CWE-295, CWE-918, CWE-352)

#### Certificate Validation Bypass
- **Emplacement** : `btnHttpsRequest_Click`
- **Code** : `ServerCertificateValidationCallback = delegate { return true; }`
- **Impact** : Attaques MITM possibles

#### SSRF (Server-Side Request Forgery)
- **Emplacement** : `btnFetchUrl_Click`
- **Problème** : Pas de validation d'URL
- **Impact** : Accès aux ressources internes

#### CSRF
- **Emplacement** : `WebService.ProcessPayment`
- **Problème** : Pas de token CSRF
- **Impact** : Actions non autorisées

### ?? Autres Vulnérabilités

#### Race Conditions (CWE-362)
- **Emplacement** : `ConcurrentService`
- **Problème** : Opérations non synchronisées
- **Exemple** : Transferts d'argent sans verrous

#### Information Disclosure (CWE-209)
- **Emplacement** : Gestion des exceptions
- **Problème** : Stack traces complètes affichées
- **Impact** : Révélation de la structure interne

#### Log Injection (CWE-117)
- **Emplacement** : `LogUserActivity`
- **Problème** : Pas de validation des entrées de log
- **Impact** : Falsification des logs

#### Insufficient Session Expiration (CWE-613)
- **Emplacement** : `CreateSession`
- **Problème** : Sessions de 10 ans
- **Impact** : Vol de session persistant

## ?? Utilisation pour les tests SAST/SCA

### 1. **Configuration**
```bash
# Cloner le repository
git clone [votre-repo]

# Ouvrir dans Visual Studio
# Installer les packages NuGet requis :
# - MongoDB.Driver (optionnel - l'app fonctionne sans)
# - Npgsql (optionnel - l'app fonctionne sans)
```

### 2. **Exécution des scans**

#### Snyk
```bash
snyk test
snyk code test
```

#### Veracode
- Upload via Veracode Platform
- Utiliser Veracode Greenlight pour IDE

#### SonarQube
```bash
dotnet sonarscanner begin /k:"vulnerable-wpf-app"
dotnet build
dotnet sonarscanner end
```

### 3. **Résultats attendus**

Les outils devraient détecter :
- ? Toutes les injections SQL/NoSQL/Command
- ? Les credentials hardcodés
- ? Les vulnérabilités cryptographiques
- ? Les problèmes d'authentification/autorisation
- ? Le stockage non sécurisé
- ? Les validations manquantes

## ?? Métriques de test

| Catégorie | Nombre de vulnérabilités | CWE couverts |
|-----------|-------------------------|--------------|
| Injection | 7 | 78, 89, 94, 611 |
| Auth/Authz | 6 | 259, 285, 306, 307 |
| Cryptographie | 5 | 321, 327, 331, 338, 759 |
| Données sensibles | 4 | 256, 311, 312, 319 |
| Validation | 4 | 22, 73, 434 |
| Réseau | 3 | 295, 352, 918 |
| Autres | 5 | 117, 209, 362, 369, 613 |

## ?? Avertissements de sécurité

1. **NE JAMAIS** déployer cette application en production
2. **NE JAMAIS** exposer sur Internet
3. **UTILISER** uniquement dans un environnement isolé
4. **SUPPRIMER** après les tests
5. **NE PAS** réutiliser le code vulnérable

## ?? Notes pour les développeurs

- Chaque vulnérabilité est intentionnelle et documentée
- Les commentaires CWE sont inclus dans le code
- L'application est conçue pour être facilement scannable
- Toutes les vulnérabilités sont accessibles depuis l'UI

## ?? Prochaines étapes

1. Exécuter les scans SAST/SCA
2. Comparer les résultats entre outils
3. Vérifier la détection de chaque catégorie
4. Documenter les faux négatifs
5. Ajuster la configuration des outils si nécessaire

---

**Rappel** : Cette application est un outil pédagogique pour tester les capacités de détection des outils de sécurité. Elle ne doit jamais être utilisée comme base pour du code de production.