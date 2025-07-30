# Application WPF Vuln�rable - Outil de Test de S�curit�

## ?? Objectif

Cette application WPF a �t� sp�cialement con�ue pour tester l'efficacit� des outils d'analyse de s�curit� statique (SAST) et d'analyse de composition logicielle (SCA) tels que Snyk, Veracode, Checkmarx, SonarQube, etc.

**?? ATTENTION : Cette application contient intentionnellement de nombreuses vuln�rabilit�s de s�curit�. NE JAMAIS d�ployer en production ou sur un environnement accessible.**

## ?? Vue d'ensemble des vuln�rabilit�s

L'application impl�mente plus de 40 vuln�rabilit�s diff�rentes couvrant les cat�gories OWASP Top 10 et de nombreux CWE (Common Weakness Enumeration).

## ?? Modifications apport�es

### 1. **Int�gration des Services Vuln�rables**
- Ajout de l'instanciation de tous les services de `VulnerableServices.cs` dans `MainWindow.xaml.cs`
- Chaque service est maintenant appel� depuis les gestionnaires d'�v�nements de l'interface utilisateur
- Cela garantit que les outils SAST d�tectent les vuln�rabilit�s car elles sont dans le flux d'ex�cution

### 2. **Nouvelle Interface Utilisateur**
- R�organisation en onglets th�matiques pour une meilleure organisation
- Ajout de groupes visuels pour s�parer les diff�rents tests
- Interface plus intuitive avec des indications sur les vuln�rabilit�s test�es
- Ajout d'un onglet de statut pour suivre les actions

### 3. **Nouveaux Boutons et Fonctionnalit�s**
- Boutons pour tester les op�rations administratives sans authentification
- Tests de t�l�chargement de fichiers
- Tests de cryptographie faible
- Interface pour les injections NoSQL et Redis

## ?? Liste d�taill�e des vuln�rabilit�s

### ?? Injections (CWE-89, CWE-78, CWE-94, CWE-611)

#### SQL Injection
- **Emplacement** : `btnLogin_Click`
- **Description** : Concat�nation directe de cha�nes dans les requ�tes SQL
- **Exemple** : `SELECT * FROM Users WHERE Username = '${username}'`
- **Impact** : Contournement d'authentification, extraction de donn�es

#### NoSQL Injection (MongoDB)
- **Emplacement** : `DatabaseService.SearchMongoDB`
- **Description** : Construction de requ�tes MongoDB par concat�nation
- **Exemple** : `{ username: '${userInput}' }`
- **Impact** : Extraction de donn�es, contournement de filtres
- **Note** : Fonctionne m�me si MongoDB n'est pas install�

#### Command Injection
- **Emplacement** : `btnExecute_Click`
- **Description** : Ex�cution directe de commandes syst�me
- **M�thodes** : `Process.Start("cmd.exe", "/c " + userInput)`
- **Impact** : Ex�cution de code arbitraire sur le serveur

#### Code Injection
- **Emplacement** : `btnEvaluate_Click`
- **Description** : Compilation et ex�cution dynamique de code C#
- **Impact** : Ex�cution de code arbitraire

#### XXE Injection
- **Emplacement** : `btnParseXML_Click`
- **Description** : Parsing XML avec DTD activ�
- **Configuration** : `DtdProcessing = DtdProcessing.Parse`
- **Impact** : Lecture de fichiers, SSRF

### ?? Authentification et Autorisation (CWE-259, CWE-285, CWE-306, CWE-307)

#### Hardcoded Credentials
- **Emplacements** : Constantes dans le code
- **Exemples** :
  - `API_KEY = "sk-1234567890abcdef"`
  - `DB_PASSWORD = "admin123"`
  - `AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"`
- **Impact** : Acc�s non autoris� aux syst�mes

#### Missing Authentication
- **Emplacement** : `AdminService`
- **M�thodes** : `DeleteAllUsers()`, `BackupDatabase()`
- **Impact** : Op�rations critiques sans authentification

#### Weak Authorization
- **Emplacement** : `AuthorizationService.IsAuthorized`
- **Probl�mes** :
  - V�rification sensible � la casse
  - Contournement par manipulation de chemins
  - Regex faible

### ?? Cryptographie (CWE-327, CWE-321, CWE-331, CWE-759)

#### Weak Cryptography
- **Algorithmes** : MD5, SHA256 sans sel
- **Mode** : ECB (Electronic Codebook)
- **Cl�s** : Hardcod�es dans le code
- **Exemple** : `byte[] key = Encoding.UTF8.GetBytes("ThisIsMySecretKey12345678901234!")`

#### Insufficient Entropy
- **Emplacement** : `TokenService`
- **Probl�me** : Utilisation de `Random` au lieu de `RandomNumberGenerator`
- **Impact** : Tokens pr�dictibles

### ?? Gestion des Donn�es Sensibles (CWE-256, CWE-311, CWE-312, CWE-319)

#### Plain Text Storage
- **Emplacement** : `DataStorageService`
- **Donn�es stock�es** :
  - Mots de passe
  - Num�ros de cartes de cr�dit
  - Cl�s API
- **Format** : Fichiers texte non chiffr�s

#### Clear Text Transmission
- **Emplacement** : `WebService.SendCredentials`
- **Probl�me** : Envoi de credentials sur HTTP
- **URL** : `http://api.example.com/login?user=${username}&pass=${password}`

### ?? Validation des Entr�es (CWE-22, CWE-73, CWE-434)

#### Path Traversal
- **Emplacement** : `btnReadFile_Click`
- **Vuln�rabilit�** : `Path.Combine(@"C:\Data\", fileName)`
- **Impact** : Lecture de fichiers arbitraires

#### Unrestricted File Upload
- **Emplacement** : `FileUploadService`
- **Probl�mes** :
  - Pas de validation du type de fichier
  - Ex�cution automatique des .exe
  - Contr�le total du chemin par l'utilisateur

### ?? Vuln�rabilit�s R�seau (CWE-295, CWE-918, CWE-352)

#### Certificate Validation Bypass
- **Emplacement** : `btnHttpsRequest_Click`
- **Code** : `ServerCertificateValidationCallback = delegate { return true; }`
- **Impact** : Attaques MITM possibles

#### SSRF (Server-Side Request Forgery)
- **Emplacement** : `btnFetchUrl_Click`
- **Probl�me** : Pas de validation d'URL
- **Impact** : Acc�s aux ressources internes

#### CSRF
- **Emplacement** : `WebService.ProcessPayment`
- **Probl�me** : Pas de token CSRF
- **Impact** : Actions non autoris�es

### ?? Autres Vuln�rabilit�s

#### Race Conditions (CWE-362)
- **Emplacement** : `ConcurrentService`
- **Probl�me** : Op�rations non synchronis�es
- **Exemple** : Transferts d'argent sans verrous

#### Information Disclosure (CWE-209)
- **Emplacement** : Gestion des exceptions
- **Probl�me** : Stack traces compl�tes affich�es
- **Impact** : R�v�lation de la structure interne

#### Log Injection (CWE-117)
- **Emplacement** : `LogUserActivity`
- **Probl�me** : Pas de validation des entr�es de log
- **Impact** : Falsification des logs

#### Insufficient Session Expiration (CWE-613)
- **Emplacement** : `CreateSession`
- **Probl�me** : Sessions de 10 ans
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

### 2. **Ex�cution des scans**

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

### 3. **R�sultats attendus**

Les outils devraient d�tecter :
- ? Toutes les injections SQL/NoSQL/Command
- ? Les credentials hardcod�s
- ? Les vuln�rabilit�s cryptographiques
- ? Les probl�mes d'authentification/autorisation
- ? Le stockage non s�curis�
- ? Les validations manquantes

## ?? M�triques de test

| Cat�gorie | Nombre de vuln�rabilit�s | CWE couverts |
|-----------|-------------------------|--------------|
| Injection | 7 | 78, 89, 94, 611 |
| Auth/Authz | 6 | 259, 285, 306, 307 |
| Cryptographie | 5 | 321, 327, 331, 338, 759 |
| Donn�es sensibles | 4 | 256, 311, 312, 319 |
| Validation | 4 | 22, 73, 434 |
| R�seau | 3 | 295, 352, 918 |
| Autres | 5 | 117, 209, 362, 369, 613 |

## ?? Avertissements de s�curit�

1. **NE JAMAIS** d�ployer cette application en production
2. **NE JAMAIS** exposer sur Internet
3. **UTILISER** uniquement dans un environnement isol�
4. **SUPPRIMER** apr�s les tests
5. **NE PAS** r�utiliser le code vuln�rable

## ?? Notes pour les d�veloppeurs

- Chaque vuln�rabilit� est intentionnelle et document�e
- Les commentaires CWE sont inclus dans le code
- L'application est con�ue pour �tre facilement scannable
- Toutes les vuln�rabilit�s sont accessibles depuis l'UI

## ?? Prochaines �tapes

1. Ex�cuter les scans SAST/SCA
2. Comparer les r�sultats entre outils
3. V�rifier la d�tection de chaque cat�gorie
4. Documenter les faux n�gatifs
5. Ajuster la configuration des outils si n�cessaire

---

**Rappel** : Cette application est un outil p�dagogique pour tester les capacit�s de d�tection des outils de s�curit�. Elle ne doit jamais �tre utilis�e comme base pour du code de production.