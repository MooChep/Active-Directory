# Déploiement d'Active Directory sur Windows Server 2022  
 
Ce projet fournit une documentation complète et détaillée sur la mise en place d'un environnement **Active Directory** (AD) sous **Windows Server 2022**, avec des machines virtuelles via VirtualBox. Il couvre la configuration des contrôleurs de domaine (AD1 et AD2), l'ajout de clients Windows 11 au domaine, la création d'unités organisationnelles (OU), de groupes et d’utilisateurs, ainsi que la mise en place de stratégies de groupe (GPO).  

La documentation inclut des scripts PowerShell permettant d’automatiser plusieurs étapes du processus, rendant l'installation plus rapide et reproductible.  

**Fonctionnalités principales :**  
✅ Déploiement d’Active Directory sur des serveurs Windows Server 2022  
✅ Automatisation des configurations réseau et des rôles AD DS et DNS  
✅ Ajout et gestion des utilisateurs, groupes et organisations via PowerShell  
✅ Création et gestion des stratégies de groupe (GPO)  
✅ Mise en place d’un partage réseau  

📌 **Technologies utilisées :**  
- Windows Server 2022  
- Windows 11  
- VirtualBox  
- PowerShell  
- Obsidian (pour la documentation)  

📖 **Comment utiliser ?**  
1. Suivez la documentation pour créer les machines virtuelles et configurer les serveurs.  
2. Exécutez les scripts PowerShell pour automatiser le processus.  
3. Ajoutez des clients au domaine et appliquez les stratégies de groupe.  

---
## Mise en place du projet 

### Prérequis :

Pour mener a bien ce projet vous aurez besoin de plusieurs choses : 
- Une machine capable de **faire fonctionner 3 VM**
- **Oracle Virtual Box** ou autre outil de virtualisation
- Deux ISO ou VM sysprep : 
	- Windows Server 2022
	- Windows 11 Client 
- Connaissance en PowerShell pour comprendre ce que vous faites.

---

## **Étape 1 : Création des VMs**

### Préparation de la VM :

Nous allons commencer par créer l'AD1 (Active Directory 1). 
1. **Mise en place de l'Active Directory 1** :
Dans Virtual Box vous devez au préalable charger vos ISO Windows Server 2022 & Windows 11. 
Afin d'éviter les problèmes je commence avec une VM initiale que je clone qui a été sysprep.
Pour obtenir un windows Sysprep: 

```PowerShell
cd C:\Windows\System32\Sysprep 
sysprep.exe
```
**Cloner la VM Windows Server :**

<img src=https://github.com/MooChep/Active-Directory/blob/main/assets/AD.png width="400">

2. **Ajouter un nom** (exemple : AD1)
3. **Sélectionner le clone lié**
Le clone lié permet d'économiser de l'espace disque
4. **Recommandé** : générer de nouvelles adresses MAC pour toutes les interfaces réseaux 

<img src=https://github.com/MooChep/Active-Directory/blob/main/assets/AD2.png width="400">

5. Dans les configurations des **VM serveur & client**, change le mode d'accès réseau en **Réseau privé hôte**. 

<img src=https://github.com/MooChep/Active-Directory/blob/main/assets/AD3.png width="400">

### Configuration des Guests Additions :

- Un message d'avertissement nous indique que les _Guests Additions_ doivent être installées. Nous allons nous occuper de ça par la suite.

<img src=https://github.com/MooChep/Active-Directory/blob/main/assets/AD4.png width="400">

1. **Noter un mot de passe Administrateur**. (Ici Admin2025!)

<img src=https://github.com/MooChep/Active-Directory/blob/main/assets/AD5.png width="400">

2. Pour installer les Guests Additions sur Virtual Box :
    - Allez dans **Périphériques > Insérer l'image CD des additions invités**. 

<img src=https://github.com/MooChep/Active-Directory/blob/main/assets/AD6.png width="400">

3. Accède au lecteur CD et lance l'exécutable **VBoxWindowsAdditions**.
4. Suis l'installateur et redémarre la machine. 

<img src=https://github.com/MooChep/Active-Directory/blob/main/assets/AD7.png width="400">

Désormais la VM est prête ! Installons l'Active Directory 1. 

## **Étape 2 : Installer l'AD1**

Lancer **PowerShell ISE** afin de simplifier la modification et l'execution des scripts. 

<img src=https://github.com/MooChep/Active-Directory/blob/main/assets/AD8.png width="400">


### Script : _setup_DC1.ps1_

Ce script va nous permettre plusieurs choses : 
- Configurer l'IP de server AD1 ainsi que du server DNS
- Ajouter l'enregistrement DNS de AD1 afin de simplifier les communications
- Promotion de l'Active Directory en tant que contrôleur de domaine principal
- Ainsi que la création 
```powershell
# Définition des variables
$MachineName = "DC1"
$DomainName = "test.local"
$NetBIOSName = "TEST"
$SafeModePassword = ConvertTo-SecureString "Admin2025" -AsPlainText -Force
$AdminPassword = ConvertTo-SecureString "Admin2025" -AsPlainText -Force
$AdminCred = New-Object System.Management.Automation.PSCredential ("Administrator", $AdminPassword)
$IPAddress = "192.168.1.10"

# Configuration de l'adresse IP statique
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress $IPAddress -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses $IPAddress

# Installation des rôles Active Directory et DNS
Install-WindowsFeature -Name AD-Domain-Services, DNS, DHCP -IncludeManagementTools

# Ajoute l'enregistrement DNS de DC1
Add-DnsServerResourceRecordA -Name $MachineName -IPv4Address $IPAddress -ZoneName $DomaineName

# Promotion en tant que contrôleur de domaine principal
Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName $NetBIOSName `
    -SafeModeAdministratorPassword $SafeModePassword `
    -InstallDNS `
    -Force

# Création d'une OU et d'un utilisateur test
New-ADOrganizationalUnit -Name "Utilisateurs" -Path "DC=test,DC=local"
New-ADUser -Name "testuser" -GivenName "Test" -Surname "User" -UserPrincipalName "testuser@test.local" -SamAccountName "testuser" -AccountPassword $AdminPassword -Enabled $true

# Redémarrage du serveur à la fin du script
$answer = Read-Host "[!] Le server va redémarrer, voulez vous continuer ? (y/n)"
if($answer -eq "y"){
Restart-Computer -Force
}

```

---

## **Étape 3 : Vérifier si AD est bien installé après redémarrage**

### Vérification via PowerShell :

Si la page de login affiche `NETID\User`, c'est bon signe !
Utilisez le mot de passe que vous avez défini à la création du compte Administrateur.

- Ouvre **PowerShell en administrateur** et exécute les commandes suivantes :

```powershell
Get-ADDomain
Get-Service adws,kdc,netlogon,dns

# Si un service est arrêté :
# Start-Service -Name <Nom_du_service>

Get-ADDomainController
Get-ADForest
Resolve-DnsName test.local
```

- Si **ces commandes fonctionnent**, l'installation est réussie ! 🎉

---

## **Étape 4 : Installer l'AD2**

### Script : _setup_AD2.ps1_

```powershell
# Définition des variables
$DomainName = "test.local"
$DC1_IP = "192.168.1.10"
$IPAddress =  "192.168.1.11"
$SafeModePassword = ConvertTo-SecureString "Admin2025" -AsPlainText -Force
$AdminPassword = ConvertTo-SecureString "Admin2025" -AsPlainText -Force
$AdminCred = New-Object System.Management.Automation.PSCredential ("TEST\Administrateur", $AdminPassword)

# 🔹 Détection automatique de l'interface réseau
$Interface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -ExpandProperty Name

if (-not $Interface) {
    Write-Host "[ERREUR] Aucune interface réseau détectée !" -ForegroundColor Red
    exit 1
}

Write-Host "[+] Interface détectée : $Interface" -ForegroundColor Cyan

# 🔹 Vérification de l'IP
$ExistingIP = Get-NetIPAddress -InterfaceAlias $Interface -AddressFamily IPv4 -ErrorAction SilentlyContinue
if ($ExistingIP.IPAddress -contains $IPAddress) {
    Write-Host "[OK] L'IP est déjà configurée." -ForegroundColor Green
} else {
    Write-Host "[+] Configuration de l'IP statique..." -ForegroundColor Yellow
    New-NetIPAddress -InterfaceAlias $Interface -IPAddress $IPAddress -PrefixLength 24 
}

# 🔹 Configuration du DNS
Write-Host "[+] Configuration du DNS..." -ForegroundColor Yellow
Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses $DC1_IP

# 🔹 Vérification de la connectivité avec DC1
Write-Host "[+] Vérification de la connectivité avec DC1 ($DC1_IP)..." -ForegroundColor Yellow
if (Test-Connection -ComputerName $DC1_IP -Count 2 -Quiet) {
    Write-Host "[OK] Connexion avec $DC1_IP réussie." -ForegroundColor Green
} else {
    Write-Host "[ERREUR] Impossible de joindre $DC1_IP !" -ForegroundColor Red
    exit 1
}

# 🔹 Installation des rôles AD DS et DNS
Write-Host "[+] Installation des rôles AD DS et DNS..." -ForegroundColor Yellow
Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools

# 🔹 Vérification du serveur DNS
Write-Host "[+] Vérification du serveur DNS..." -ForegroundColor Yellow
if (Resolve-DnsName $DomainName -ErrorAction SilentlyContinue) {
    Write-Host "[OK] DNS résout $DomainName correctement." -ForegroundColor Green
} else {
    Write-Host "[ERREUR] Impossible de résoudre $DomainName. Vérifie que DC1 est bien configuré comme DNS !" -ForegroundColor Red
    exit 1
}

# 🔹 Vérification si l'ordinateur est déjà dans le domaine
$Domain = Get-ADDomainController -Filter {Domain -eq $DomainName}

if ($Domain -eq $DomainName) {
    Write-Host "[OK] L'ordinateur fait déjà partie du domaine $DomainName. Pas besoin de l'ajouter." -ForegroundColor Green
} else {
    Write-Host "[+] Ajout du serveur au domaine $DomainName..." -ForegroundColor Yellow
    try {
       Import-Module ADDSDeployment
    Install-ADDSDomainController `
        -NoGlobalCatalog:$true `
        -CreateDnsDelegation:$false `
        -Credential (Get-Credential) `
        -CriticalReplicationOnly:$false `
        -DatabasePath "C:\Windows\NTDS" `
        -DomainName $DomainName `
        -InstallDns:$true `
        -LogPath "C:\Windows\NTDS" `
        -NoRebootOnCompletion:$false `
        -SiteName "Default-First-Site-Name" `
        -SysvolPath "C:\Windows\SYSVOL" `
        -Force:$true
    } catch {
        Write-Host "[ERREUR] Échec de l'ajout au domaine : $_" -ForegroundColor Red
        exit 1
    }
}
```

**Get-Credentials** : Il faut renseigner le nom d'utilisateur complet et le mot de passe du compte Administrateur de l'AD1
Ici c'est :
*user*: TEST\Administrateur
*password*: Admin2025!

**Bonus :** Ajouter l'enregistrement de **DC2** depuis le serveur DNS :
(Attention si vous avez utilisé un autre nom de domaine ou une autre adresse IP)
```powershell
Add-DnsServerResourceRecordA -Name "DC2" -IPv4Address "192.168.1.11" -ZoneName "test.local"
```

---

## **Étape 5 : Vérifier si AD2 est bien dans le domaine**

Après la réalisation de l'étape 4, on vérifie qu'elle a bien été réalisé.

```powershell
$ComputerDomain = (Get-WmiObject -Class Win32_ComputerSystem).Domain
Write-Host "[-] Ce serveur est dans le domaine : $ComputerDomain" -ForegroundColor Cyan
```

- Si la valeur retournée est le nom du domaine (ex. : `test.local`), alors le serveur fait bien partie du domaine.
Autre méthode : 
Vérifiez dans la fenêtre d'interface "Utilisateur et ordinateur Active Directory" si AD1 & AD2 sont présents alors c'est réussi ! 

---

## **Étape 6 : Installation Client Windows 11**

Pour ajouter un windows 11 au domaine on execute ce script sur la VM client Win11

Ce script teste la connexion avec l'Active Directory 1 puis ajoute le PC grâce à l'accès Administrateur donnée par $Credential :

**Important** : Pour que le script réponde il faut que le server AD1 soit en marche.
```powershell
# Définition des variables
$DomainName = "test.local"
$AdminUser = "Administrateur"
$AdminPassword = ConvertTo-SecureString "Admin2025" -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ("$DomainName\$AdminUser", $AdminPassword)

# Configuration de l'adresse IP et du DNS
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress "192.168.1.50" -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "192.168.1.10"

# Vérification de la connectivité avec le DController de l'AD1
Test-Connection -ComputerName "192.168.1.10" -Count 4

Add-Computer -DomainName $DomainName -Credential $Credential
```

On peut vérifier l'ajout de l'Ordinateur au domaine dans l'onglet `Computeurs` de `Utilisateur et ordinateur Active Directory`

---
## **Étape 7 : Création des OU (Organizational Unit)**

```PowerShell
$OUName = "Utilisateurs"
# Récuperer le nom du domaine automatiquement
$Domain = (Get-ADDomain).DistinguishedName 

if(Get-ADOrganizationalUnit -Filter "Name -eq '$OUName'" -ErrorAction SilentlyContinue){
	Write-Host "[OK] '$OUName' Existe déjà dans le domaine !" -ForegroundColor Yellow 
} else {
	New-ADOrganizationalUnit -Name $OUName -Path $Domain -ProtectedFromAccidentalDeletion $true
	Write-Host "[+] '$OUName' a bien été créée ! " -ForegroundColor Green
}


```


---
## **Étape 8 : Création des groupes**

```PowerShell 
$GroupName = "WindowsServer"

$OUName

if(Get-ADGroup -Filter {Name -eq $GroupName}){

    Write-Host "[OK] Le groupe '$GroupName' existe déjà." -ForegroundColor Yellow

} else {

    New-ADGroup -Name $GroupName -Path "OU=$OUName,DC=TEST,DC=LOCAL" -GroupScope Global

    Write-Host "[+] Le groupe '$GroupName' a bien été créé." -ForegroundColor Green

}
```
---
## **Étape 9 : Création des utilisateurs**

Cette partie a pour but d'avoir un Active Directory rempli d'utilisateur afin de pouvoir gérer les groupes, organisation et GPO avec de vrais compte utilisateurs.
### Script : _create_users.ps1_

```PowerShell
Import-Module ActiveDirectory 

# 🔹 Définition des variables
$DomainName = "test.local"
$OU = "OU=Utilisateurs,DC=test,DC=local"
$MotDePasse = ConvertTo-SecureString "User2025!" -AsPlainText -Force
$Groupe = "Utilisateurs du domaine"

# 🔹 Vérification de l'OU
Write-Host "[+] Vérification de l'existence de l'OU $OU..." -ForegroundColor Cyan
$OUExiste = Get-ADOrganizationalUnit -Filter {DistinguishedName -eq $OU} -ErrorAction SilentlyContinue 

if ($OUExiste) {
    Write-Host "[OK] L'OU $OU existe déjà." -ForegroundColor Green
} else {
    Write-Host "[+] Création de l'OU $OU..." -ForegroundColor Yellow
    try {
        New-ADOrganizationalUnit -Name "Utilisateurs" -Path "DC=mondomaine,DC=local"
        Write-Host "[OK] L'OU a été créée avec succès." -ForegroundColor Green
    } catch {
        Write-Host "[ERREUR] Impossible de créer l'OU : $_" -ForegroundColor Red
        exit 1
    }
}

# 🔹 Liste des utilisateurs à créer
$Utilisateurs = @(
    @{Prenom="Alice"; Nom="Durand"},
    @{Prenom="Bob"; Nom="Martin"},
    @{Prenom="Charlie"; Nom="Lemoine"},
    @{Prenom="David"; Nom="Morel"},
    @{Prenom="Emma"; Nom="Bernard"},
    @{Prenom="Fabien"; Nom="Gauthier"},
    @{Prenom="Gabriel"; Nom="Rousseau"},
    @{Prenom="Hugo"; Nom="Chevalier"},
    @{Prenom="Isabelle"; Nom="Guillot"},
    @{Prenom="Julien"; Nom="Roy"},
    @{Prenom="Kevin"; Nom="Leroy"},
    @{Prenom="Laura"; Nom="Meyer"},
    @{Prenom="Manon"; Nom="Giraud"},
    @{Prenom="Nathan"; Nom="Adam"},
    @{Prenom="Olivier"; Nom="Perrin"},
    @{Prenom="Paul"; Nom="Dupont"},
    @{Prenom="Quentin"; Nom="Schneider"},
    @{Prenom="Raphaël"; Nom="Marchal"},
    @{Prenom="Sophie"; Nom="Renard"},
    @{Prenom="Thomas"; Nom="Benoit"}
)

# 🔹 Création des utilisateurs
foreach ($utilisateur in $Utilisateurs) {
    $NomUtilisateur = ($utilisateur.Prenom.Substring(0,1) + $utilisateur.Nom).ToLower()
    
    Write-Host "[+] Vérification de l'existence de l'utilisateur $NomUtilisateur..." -ForegroundColor Cyan
    $UtilisateurExiste = Get-ADUsesay jr -Filter {SamAccountName -eq $NomUtilisateur} -ErrorAction SilentlyContinue
    
    if ($UtilisateurExiste) {
        Write-Host "[OK] L'utilisateur $NomUtilisateur existe déjà." -ForegroundColor Green
    } else {
        Write-Host "[+] Création de l'utilisateur $NomUtilisateur..." -ForegroundColor Yellow
        try {
            New-ADUser -SamAccountName $NomUtilisateur `
                -UserPrincipalName "$NomUtilisateur@$DomainName" `
                -Name "$($utilisateur.Prenom) $($utilisateur.Nom)" `
                -GivenName $utilisateur.Prenom `
                -Surname $utilisateur.Nom `
                -DisplayName "$($utilisateur.Prenom) $($utilisateur.Nom)" `
                -Path $OU `
                -AccountPassword $MotDePasse `
                -Enabled $true
            
            Write-Host "[OK] Utilisateur $NomUtilisateur créé avec succès." -ForegroundColor Green
            
            # 🔹 Ajout au groupe
            Write-Host "[+] Ajout de l'utilisateur $NomUtilisateur au groupe $Groupe..." -ForegroundColor Cyan
            Add-ADGroupMember -Identity $Groupe -Members $NomUtilisateur
            Write-Host "[OK] Utilisateur $NomUtilisateur ajouté au groupe $Groupe." -ForegroundColor Green
        } catch {
            Write-Host "[ERREUR] Échec de la création de l'utilisateur $NomUtilisateur : $_" -ForegroundColor Red
        }
    }
}

```

Pour supprimer un utilisateur : 

```PowerShell
$UserName = "JDoe"
$OUPath = "OU=Utilisateurs,DC=test,DC=local"

#Verification que l'utilisateur existe:
$User = Get-ADUser -Filter {SamAccountName -eq $UserName} -SearchBase $OUPath -ErrorAction SilentlyContinue

if($User){
	Write-Host "[OK] Suppression de l'utilisateur '$UserName'" -ForegroundColor Green
	Remove-ADUser -Identity $User -Confirm:$false
}else {
	Write-Host "[ERROR] L'utilisateur '$UserName' n'existe pas dans l'OU '$OUPath'" -ForegroundColor Red
}
```


---
## **Étape 10 : Création d'un partage réseau**

```PowerShell
$shareName = "windows"
$sharePath ="C:\Share"

# Verification si le dossier existe, sinon le créer
if(-Not (Test-Path $sharePath)){
    New-Item -ItemType Directory -Path $sharePath -Force | Out-Null
    Write-Host "[+] Le dossier '$sharePath' a été créé." -ForegroundColor Green
}
# Vérifier si le partage existe
$existingShare = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue

if($existingShare -eq $null){
    # Création du partage si il n'existe pas
    New-SmbShare -Name $shareName -Path $sharePath -FullAccess "Everyone"
    Write-Host "[+] Le partage '$shareName' a été crée" -ForegroundColor Green
}else {
    Write-Host "[OK] Le partage '$shareName' existe déjà" -ForegroundColor Yellow
}
```

---
## **Étape 11 : Installation GPO**

### Script : _install_GPO.ps1_
```PowerShell
Import-Module GroupPolicy

# 🔹 Définition des variables
$gpoName = "SimpleGPO"
$backupPath = "C:\Users\Administrateur\Documents\SauvegardeGPO"
$regKey = "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$regValue1 = "DisallowRun"
$regValue2 = "RestrictRun"

# 🔹 Vérification de l'existence de la GPO
Write-Host "[+] Vérification de l'existence de la GPO '$gpoName'..." -ForegroundColor Cyan
$existingGpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue

if (-not $existingGpo) {
    Write-Host "[+] Création de la GPO '$gpoName'..." -ForegroundColor Yellow
    try {
        $gpo = New-GPO -Name $gpoName
        Write-Host "[OK] La GPO '$gpoName' a été créée." -ForegroundColor Green
    } catch {
        Write-Host "[ERREUR] Impossible de créer la GPO : $_" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[OK] La GPO '$gpoName' existe déjà." -ForegroundColor Green
}

# 🔹 Vérification et création du répertoire de sauvegarde
if (-not (Test-Path -Path $backupPath)) {
    Write-Host "[+] Création du répertoire de sauvegarde '$backupPath'..." -ForegroundColor Yellow
    New-Item -Path $backupPath -ItemType Directory
    Write-Host "[OK] Répertoire de sauvegarde créé." -ForegroundColor Green
}

# 🔹 Sauvegarde de la GPO
Write-Host "[+] Sauvegarde de la GPO '$gpoName'..." -ForegroundColor Yellow
Backup-GPO -Name $gpoName -Path $backupPath
Write-Host "[OK] La GPO '$gpoName' a été sauvegardée dans '$backupPath'." -ForegroundColor Green

# 🔹 Vérification du lien de la GPO au domaine
$gplink = Get-GPLink -Name $gpoName -ErrorAction SilentlyContinue
if (-not $gplink) {
    Write-Host "[+] Liaison de la GPO '$gpoName' au domaine..." -ForegroundColor Yellow
    New-GPLink -Name $gpoName -Target "DC=test,DC=local"
    Write-Host "[OK] La GPO '$gpoName' a été liée au domaine." -ForegroundColor Green
} else {
    Write-Host "[OK] La GPO '$gpoName' est déjà liée au domaine." -ForegroundColor Green
}

# 🔹 Vérification et configuration des paramètres de registre
Write-Host "[+] Vérification et configuration des paramètres de registre..." -ForegroundColor Yellow
$existingValue1 = Get-GPRegistryValue -Name $gpoName -Key $regKey -ValueName $regValue1 -ErrorAction SilentlyContinue
if (-not $existingValue1) {
    Set-GPRegistryValue -Name $gpoName -Key $regKey -ValueName $regValue1 -Type DWord -Value 1
    Write-Host "[OK] La valeur de registre '$regValue1' a été définie." -ForegroundColor Green
} else {
    Write-Host "[OK] La valeur de registre '$regValue1' est déjà configurée." -ForegroundColor Green
}

$existingValue2 = Get-GPRegistryValue -Name $gpoName -Key $regKey -ValueName $regValue2 -ErrorAction SilentlyContinue
if (-not $existingValue2) {
    Set-GPRegistryValue -Name $gpoName -Key $regKey -ValueName $regValue2 -Type MultiString -Value "cmd.exe"
    Write-Host "[OK] La valeur de registre '$regValue2' a été définie." -ForegroundColor Green
} else {
    Write-Host "[OK] La valeur de registre '$regValue2' est déjà configurée." -ForegroundColor Green
}

# 🔹 Forcer une mise à jour des GPO
Write-Host "[+] Mise à jour des GPO en cours..." -ForegroundColor Yellow
gpupdate /force
Write-Host "[OK] Mise à jour des GPO effectuée." -ForegroundColor Green

```


Une fois créée on peut définir des règles pour la GPO.
Ces règles peuvent être :
- **Importées** :
```PowerShell
Import-GPO -Path "C:\Users\Administrateur\Documents\SauvegardeGPO" -TargetName "SimpleGPO"
```
- **Copiées** : 
```PowerShell
Copy-GPO -SourceName "SimpleGPO" -TargetName "AutreGPO" -TargetDomain "test.local"
```
- **Sauvegardées** :
```PowerShell
Backup-GPO -Name "MaGPO" -Path "C:\Users\Administrateur\Documents\SauvegardeGPOs"
```


Mais **surtout** elles doivent être **liées** à un domaine pour être utiles.

```PowerShell
New-GPLink -Name "SimpleGPO" -Target "DC=test,DC=local"
Set-GPRegistryValue -Name "SimpleGPO" -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "DisallowRun" -Type DWord -Value 1 Set-GPRegistryValue -Name "SimpleGPO" -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "RestrictRun" -Type MultiString -Value "cmd.exe" gpupdate /force
```

Pour ajouter des règles nous devons utiliser l'interface graphique.

Le plus souvent les GPO sont importées car le minimum requis en terme de sécurité est commun a beaucoup de domaine. 
Cependant on peut être très précis dans les droits utilisateurs et les accès au outils grâce aux GPO.

Microsoft met a disposition des ressources concernant les bonnes pratiques pour les GPO, depuis leur site on peut importer dans notre domaine un exemple de GPO.

Pour appliquer une GPO préconfigurée à votre domaine, voici les étapes à suivre :

---
## **Étape 12 : Importer une GPO**

Recuperez le fichier sur le site de [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=55319) et suivez les instructions d'installation.

#### **Option 1 : via la console de gestion des stratégies de groupe (GPMC)**

1. **Ouvrir la console GPMC**  
    → Tapez `gpmc.msc` dans Exécuter (`Win + R`) et validez.
    
2. **Créer une nouvelle GPO (ou utiliser une existante)**
    
    - Faites un clic droit sur le domaine ou une Unité d’Organisation (OU) cible.
    - Sélectionnez **Créer un objet GPO dans ce domaine et le lier ici**.
    - Donnez-lui un nom explicite (ex: **Sécurité_Entreprise**).
3. **Importer la GPO préconfigurée**
    
    - Faites un clic droit sur la GPO et sélectionnez **Importer les paramètres**.
    - Suivez l’assistant et **sélectionnez le dossier contenant la GPO préconfigurée**.

#### **Option 2 : Via PowerShell**

Si vous avez un fichier de sauvegarde `.bak` de GPO :

```powershell
Import-GPO -BackupGpoName "NomDeLaGPO" -TargetName "NomDeLaNouvelleGPO" -Path "C:\Chemin\Vers\La\Sauvegarde"
```

---

### **2. Lier la GPO à votre domaine**

Une fois la GPO créée ou importée, vous devez l’appliquer à une OU ou au domaine entier :

```powershell
New-GPLink -Name "NomDeLaGPO" -Target "OU=Utilisateurs,DC=test,DC=local"
```

Ou directement sur le domaine :

```powershell
New-GPLink -Name "NomDeLaGPO" -Target "DC=test,DC=local"
```

---

### **3. Forcer l'application de la GPO immédiatement**

Par défaut, les GPO sont appliquées à la prochaine actualisation des stratégies (toutes les 90 minutes avec un décalage aléatoire de 0 à 30 minutes). Pour accélérer le processus :

#### **Sur le serveur**

```powershell
gpupdate /force
```

#### **Sur un client**

```powershell
gpupdate /force
```

Si la GPO configure des paramètres utilisateur, demandez aux utilisateurs concernés de redémarrer ou de se reconnecter.

---

### **4. Vérifier que la GPO est bien appliquée**

#### **Via PowerShell sur un client**

```powershell
gpresult /r
```

Ou générer un rapport détaillé en HTML :

```powershell
gpresult /h C:\gporeport.html
start C:\gporeport.html
```


---


## **Félicitation !**

Voila le projet terminé, Maintenant nous avons un domaine fonctionnel, sécurisé et peuplé de groupes et utilisateurs. 



*Sources : ItConnect, Microsoft, OpenClassrooms, Collaboration avec mes camarades de promotion*

*Outils Utilisés : 
*[Oracle Virtual Box](https://www.virtualbox.org/)
[Obsidian](https://obsidian.md/) (Redaction de la documentation)
[ChatGPT](https://chatgpt.com) (Mise en forme et commandes précises pour les scripts)*

