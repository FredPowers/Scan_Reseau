  <#
.NOTES
	NAME:	Scan_Reseau.ps1
    VERSION : 1.0  17/05/2022
    VERSION : 1.1  18/06/2022
	AUTHOR:	Frédéric Puren


VERSION 1.1 :

- Amélioration du script en intégrant une fonction pour le calcul réseau.
- Ajout du scope d'adresse IP d'un second réseau si un VPN est connecté.


  Sources : 

  faire un menu : https://wiki-tech.io/Scripting/Powershell/Menu

  pour convertir decimal vers binaire et vice versa : https://devblogs.microsoft.com/scripting/use-powershell-to-easily-convert-decimal-to-binary-and-back/

  séparer des chaines de caractère : https://www.it-connect.fr/powershell-et-split-decouper-une-chaine-de-caracteres/

  extraire une chaine de caractère : https://www.it-connect.fr/powershell-et-substring-extraire-une-chaine-dune-chaine/

  padleft, padright : https://4sysops.com/archives/how-to-add-leading-and-ending-zeroes-to-strings-in-powershell/

  créer une fonction : https://techexpert.tips/fr/powershell-fr/powershell-creation-dune-fonction/
  
  Scan réseau en /24 : https://www.pentest.school/blog/scanner-un-reseau-avec-powershell

  Scan de ports : https://jonlabelle.com/snippets/view/powershell/powershell-script-to-scan-open-ports
#>


# ------------------------------------------------------------------------------------------------------------------   
 
 #Fonction pour le calcul de l'Adresse réseau, adresse Broadcast, premier hote, dernier hote et nombre d'hotes total.
 

function Calcul_Reseaux($AdresseIP,$Masque) {

    # Calcul

    # séparation des 4 éléments séparés par les points
$AdresseIPSplit = $AdresseIP.Split(".")

$a = $AdresseIPSplit[0]
$b = $AdresseIPSplit[1]
$c = $AdresseIPSplit[2]
$d = $AdresseIPSplit[3]

# conversion en base 2
$a_binaire = [convert]::ToString($a,2)
$b_binaire = [convert]::ToString($b,2)
$c_binaire = [convert]::ToString($c,2)
$d_binaire = [convert]::ToString($d,2)

#ajout de 0 à gauche avec un maximum de 8 chiffres au total
$a_binaireOctet = $a_binaire.PadLeft(8,'0')
$b_binaireOctet = $b_binaire.PadLeft(8,'0')
$c_binaireOctet = $c_binaire.PadLeft(8,'0')
$d_binaireOctet = $d_binaire.PadLeft(8,'0')

$Conversion_AdresseIP = "$a_binaireOctet.$b_binaireOctet.$c_binaireOctet.$d_binaireOctet"

#---------------------------------------------------------------------------------------

# conversion du masque de sous-réseau en Binaire

$MasqueSplit = $Masque.Split(".")

$e = $MasqueSplit[0]
$f = $MasqueSplit[1]
$g = $MasqueSplit[2]
$h = $MasqueSplit[3]

# conversion en base 2
$e_binaire = [convert]::ToString($e,2)
$f_binaire = [convert]::ToString($f,2)
$g_binaire = [convert]::ToString($g,2)
$h_binaire = [convert]::ToString($h,2)

#ajout de 0 à gauche avec un maximum de 8 chiffres au total
$e_binaireOctet = $e_binaire.PadLeft(8,'0')
$f_binaireOctet = $f_binaire.PadLeft(8,'0')
$g_binaireOctet = $g_binaire.PadLeft(8,'0')
$h_binaireOctet = $h_binaire.PadLeft(8,'0')

$Conversion_Masque = "$e_binaireOctet.$f_binaireOctet.$g_binaireOctet.$h_binaireOctet"

#---------------------------------------------------------------------------------------

# calcul de l'adresse réseau


#séparation de chaque caractère des adresses IP et Masque pour correspondance de chaque Bit ( 1+1=1, 1+0=0 , 0+0=0 )

# partie Adresse IP
$chiffre1 = $Conversion_AdresseIP[0]
$chiffre2 = $Conversion_AdresseIP[1]
$chiffre3 = $Conversion_AdresseIP[2]
$chiffre4 = $Conversion_AdresseIP[3]
$chiffre5 = $Conversion_AdresseIP[4]
$chiffre6 = $Conversion_AdresseIP[5]
$chiffre7 = $Conversion_AdresseIP[6]
$chiffre8 = $Conversion_AdresseIP[7]
$chiffre9 = $Conversion_AdresseIP[9]
$chiffre10 = $Conversion_AdresseIP[10]
$chiffre11 = $Conversion_AdresseIP[11]
$chiffre12 = $Conversion_AdresseIP[12]
$chiffre13 = $Conversion_AdresseIP[13]
$chiffre14 = $Conversion_AdresseIP[14]
$chiffre15 = $Conversion_AdresseIP[15]
$chiffre16 = $Conversion_AdresseIP[16]
$chiffre17 = $Conversion_AdresseIP[18]
$chiffre18 = $Conversion_AdresseIP[19]
$chiffre19 = $Conversion_AdresseIP[20]
$chiffre20 = $Conversion_AdresseIP[21]
$chiffre21 = $Conversion_AdresseIP[22]
$chiffre22 = $Conversion_AdresseIP[23]
$chiffre23 = $Conversion_AdresseIP[24]
$chiffre24 = $Conversion_AdresseIP[25]
$chiffre25 = $Conversion_AdresseIP[27]
$chiffre26 = $Conversion_AdresseIP[28]
$chiffre27 = $Conversion_AdresseIP[29]
$chiffre28 = $Conversion_AdresseIP[30]
$chiffre29 = $Conversion_AdresseIP[31]
$chiffre30 = $Conversion_AdresseIP[32]
$chiffre31 = $Conversion_AdresseIP[33]
$chiffre32 = $Conversion_AdresseIP[34]

# partie Masque
$chiffre1a = $Conversion_Masque[0]
$chiffre2a = $Conversion_Masque[1]
$chiffre3a = $Conversion_Masque[2]
$chiffre4a = $Conversion_Masque[3]
$chiffre5a = $Conversion_Masque[4]
$chiffre6a = $Conversion_Masque[5]
$chiffre7a = $Conversion_Masque[6]
$chiffre8a = $Conversion_Masque[7]
$chiffre9a = $Conversion_Masque[9]
$chiffre10a = $Conversion_Masque[10]
$chiffre11a = $Conversion_Masque[11]
$chiffre12a = $Conversion_Masque[12]
$chiffre13a = $Conversion_Masque[13]
$chiffre14a = $Conversion_Masque[14]
$chiffre15a = $Conversion_Masque[15]
$chiffre16a = $Conversion_Masque[16]
$chiffre17a = $Conversion_Masque[18]
$chiffre18a = $Conversion_Masque[19]
$chiffre19a = $Conversion_Masque[20]
$chiffre20a = $Conversion_Masque[21]
$chiffre21a = $Conversion_Masque[22]
$chiffre22a = $Conversion_Masque[23]
$chiffre23a = $Conversion_Masque[24]
$chiffre24a = $Conversion_Masque[25]
$chiffre25a = $Conversion_Masque[27]
$chiffre26a = $Conversion_Masque[28]
$chiffre27a = $Conversion_Masque[29]
$chiffre28a = $Conversion_Masque[30]
$chiffre29a = $Conversion_Masque[31]
$chiffre30a = $Conversion_Masque[32]
$chiffre31a = $Conversion_Masque[33]
$chiffre32a = $Conversion_Masque[34]


[int] $resultat1 = $chiffre1 + $chiffre1a
[int] $resultat2 = $chiffre2 + $chiffre2a
[int] $resultat3 = $chiffre3 + $chiffre3a
[int] $resultat4 = $chiffre4 + $chiffre4a
[int] $resultat5 = $chiffre5 + $chiffre5a
[int] $resultat6 = $chiffre6 + $chiffre6a
[int] $resultat7 = $chiffre7 + $chiffre7a
[int] $resultat8 = $chiffre8 + $chiffre8a
[int] $resultat9 = $chiffre9 + $chiffre9a
[int] $resultat10 = $chiffre10 + $chiffre10a
[int] $resultat11 = $chiffre11 + $chiffre11a
[int] $resultat12 = $chiffre12 + $chiffre12a
[int] $resultat13 = $chiffre13 + $chiffre13a
[int] $resultat14 = $chiffre14 + $chiffre14a
[int] $resultat15 = $chiffre15 + $chiffre15a
[int] $resultat16 = $chiffre16 + $chiffre16a
[int] $resultat17 = $chiffre17 + $chiffre17a
[int] $resultat18 = $chiffre18 + $chiffre18a
[int] $resultat19 = $chiffre19 + $chiffre19a
[int] $resultat20 = $chiffre20 + $chiffre20a
[int] $resultat21 = $chiffre21 + $chiffre21a
[int] $resultat22 = $chiffre22 + $chiffre22a
[int] $resultat23 = $chiffre23 + $chiffre23a
[int] $resultat24 = $chiffre24 + $chiffre24a
[int] $resultat25 = $chiffre25 + $chiffre25a
[int] $resultat26 = $chiffre26 + $chiffre26a
[int] $resultat27 = $chiffre27 + $chiffre27a
[int] $resultat28 = $chiffre28 + $chiffre28a
[int] $resultat29 = $chiffre29 + $chiffre29a
[int] $resultat30 = $chiffre30 + $chiffre30a
[int] $resultat31 = $chiffre31 + $chiffre31a
[int] $resultat32 = $chiffre32 + $chiffre32a
[int] $resultat33 = $chiffre33 + $chiffre33a
[int] $resultat34 = $chiffre34 + $chiffre34a

# les résultats ci-dessus donne soit 00(0) soit 01(1) soit 10 soit 11, pour avoir l'adresse du réseau : 0 et 0 donne 0, 1 et 0 donne 0 et 1 et 1 donne 1.
if ($resultat1 -eq 0 -or $resultat1 -eq 1 -or $resultat1 -eq 10)

{
$resultatBinaire1 = 0
}

if ($resultat1 -eq 11)

{
$resultatBinaire1 = 1
}

if ($resultat2 -eq 0 -or $resultat2 -eq 1 -or $resultat2 -eq 10)

{
$resultatBinaire2 = 0
}

if ($resultat2 -eq 11)

{
$resultatBinaire2 = 1
}

if ($resultat3 -eq 0 -or $resultat3 -eq 1 -or $resultat3 -eq 10)

{
$resultatBinaire3 = 0
}

if ($resultat3 -eq 11)

{
$resultatBinaire3 = 1
}

if ($resultat4 -eq 0 -or $resultat4 -eq 1 -or $resultat4 -eq 10)

{
$resultatBinaire4 = 0
}

if ($resultat4 -eq 11)

{
$resultatBinaire4 = 1
}

if ($resultat5 -eq 0 -or $resultat5 -eq 1 -or $resultat5 -eq 10)

{
$resultatBinaire5 = 0
}

if ($resultat5 -eq 11)

{
$resultatBinaire5 = 1
}

if ($resultat6 -eq 0 -or $resultat6 -eq 1 -or $resultat6 -eq 10)

{
$resultatBinaire6 = 0
}

if ($resultat6 -eq 11)

{
$resultatBinaire6 = 1
}

if ($resultat7 -eq 0 -or $resultat7 -eq 1 -or $resultat7 -eq 10)

{
$resultatBinaire7 = 0
}

if ($resultat7 -eq 11)

{
$resultatBinaire7 = 1
}

if ($resultat8 -eq 0 -or $resultat8 -eq 1 -or $resultat8 -eq 10)

{
$resultatBinaire8 = 0
}

if ($resultat8 -eq 11)

{
$resultatBinaire8 = 1
}

if ($resultat9 -eq 0 -or $resultat9 -eq 1 -or $resultat9 -eq 10)

{
$resultatBinaire9 = 0
}

if ($resultat9 -eq 11)

{
$resultatBinaire9 = 1
}

if ($resultat10 -eq 0 -or $resultat10 -eq 1 -or $resultat10 -eq 10)

{
$resultatBinaire10 = 0
}

if ($resultat10 -eq 11)

{
$resultatBinaire10 = 1
}

if ($resultat11 -eq 0 -or $resultat11 -eq 1 -or $resultat11 -eq 10)

{
$resultatBinaire11 = 0
}

if ($resultat11 -eq 11)

{
$resultatBinaire11 = 1
}

if ($resultat12 -eq 0 -or $resultat12 -eq 1 -or $resultat12 -eq 10)

{
$resultatBinaire12 = 0
}

if ($resultat12 -eq 11)

{
$resultatBinaire12 = 1
}

if ($resultat13 -eq 0 -or $resultat13 -eq 1 -or $resultat13 -eq 10)

{
$resultatBinaire13 = 0
}

if ($resultat13 -eq 11)

{
$resultatBinaire13 = 1
}

if ($resultat14 -eq 0 -or $resultat14 -eq 1 -or $resultat14 -eq 10)

{
$resultatBinaire14 = 0
}

if ($resultat14 -eq 11)

{
$resultatBinaire14 = 1
}

if ($resultat15 -eq 0 -or $resultat15 -eq 1 -or $resultat15 -eq 10)

{
$resultatBinaire15 = 0
}

if ($resultat15 -eq 11)

{
$resultatBinaire15 = 1
}

if ($resultat16 -eq 0 -or $resultat16 -eq 1 -or $resultat16 -eq 10)

{
$resultatBinaire16 = 0
}

if ($resultat16 -eq 11)

{
$resultatBinaire16 = 1
}

if ($resultat17 -eq 0 -or $resultat17 -eq 1 -or $resultat17 -eq 10)

{
$resultatBinaire17 = 0
}

if ($resultat17 -eq 11)

{
$resultatBinaire17 = 1
}

if ($resultat18 -eq 0 -or $resultat18 -eq 1 -or $resultat18 -eq 10)

{
$resultatBinaire18 = 0
}

if ($resultat18 -eq 11)

{
$resultatBinaire18 = 1
}

if ($resultat19 -eq 0 -or $resultat19 -eq 1 -or $resultat19 -eq 10)

{
$resultatBinaire19 = 0
}

if ($resultat19 -eq 11)

{
$resultatBinaire19 = 1
}

if ($resultat20 -eq 0 -or $resultat20 -eq 1 -or $resultat20 -eq 10)

{
$resultatBinaire20 = 0
}

if ($resultat20 -eq 11)

{
$resultatBinaire20 = 1
}

if ($resultat21 -eq 0 -or $resultat21 -eq 1 -or $resultat21 -eq 10)

{
$resultatBinaire21 = 0
}

if ($resultat21 -eq 11)

{
$resultatBinaire21 = 1
}

if ($resultat22 -eq 0 -or $resultat22 -eq 1 -or $resultat22 -eq 10)

{
$resultatBinaire22 = 0
}

if ($resultat22 -eq 11)

{
$resultatBinaire22 = 1
}

if ($resultat23 -eq 0 -or $resultat23 -eq 1 -or $resultat23 -eq 10)

{
$resultatBinaire23 = 0
}

if ($resultat23 -eq 11)

{
$resultatBinaire23 = 1
}

if ($resultat24 -eq 0 -or $resultat24 -eq 1 -or $resultat24 -eq 10)

{
$resultatBinaire24 = 0
}

if ($resultat24 -eq 11)

{
$resultatBinaire24 = 1
}

if ($resultat25 -eq 0 -or $resultat25 -eq 1 -or $resultat25 -eq 10)

{
$resultatBinaire25 = 0
}

if ($resultat25 -eq 11)

{
$resultatBinaire25 = 1
}

if ($resultat26 -eq 0 -or $resultat26 -eq 1 -or $resultat26 -eq 10)

{
$resultatBinaire26 = 0
}

if ($resultat26 -eq 11)

{
$resultatBinaire26 = 1
}

if ($resultat27 -eq 0 -or $resultat27 -eq 1 -or $resultat27 -eq 10)

{
$resultatBinaire27 = 0
}

if ($resultat27 -eq 11)

{
$resultatBinaire27 = 1
}

if ($resultat28 -eq 0 -or $resultat28 -eq 1 -or $resultat28 -eq 10)

{
$resultatBinaire28 = 0
}

if ($resultat28 -eq 11)

{
$resultatBinaire28 = 1
}

if ($resultat29 -eq 0 -or $resultat29 -eq 1 -or $resultat29 -eq 10)

{
$resultatBinaire29 = 0
}

if ($resultat29 -eq 11)

{
$resultatBinaire29 = 1
}

if ($resultat30 -eq 0 -or $resultat30 -eq 1 -or $resultat30 -eq 10)

{
$resultatBinaire30 = 0
}

if ($resultat30 -eq 11)

{
$resultatBinaire30 = 1
}

if ($resultat31 -eq 0 -or $resultat31 -eq 1 -or $resultat31 -eq 10)

{
$resultatBinaire31 = 0
}

if ($resultat31 -eq 11)

{
$resultatBinaire31 = 1
}

if ($resultat32 -eq 0 -or $resultat32 -eq 1 -or $resultat32 -eq 10)

{
$resultatBinaire32 = 0
}

if ($resultat32 -eq 11)

{
$resultatBinaire32 = 1
}


#--------------------------------------------------------------------------------
# calcul de l'adresse du réseau

$calcul_adresse_reseau_Binaire = "$resultatBinaire1$resultatBinaire2$resultatBinaire3$resultatBinaire4$resultatBinaire5$resultatBinaire6$resultatBinaire7$resultatBinaire8.$resultatBinaire9$resultatBinaire10$resultatBinaire11$resultatBinaire12$resultatBinaire13$resultatBinaire14$resultatBinaire15$resultatBinaire16.$resultatBinaire17$resultatBinaire18$resultatBinaire19$resultatBinaire20$resultatBinaire21$resultatBinaire22$resultatBinaire23$resultatBinaire24.$resultatBinaire25$resultatBinaire26$resultatBinaire27$resultatBinaire28$resultatBinaire29$resultatBinaire30$resultatBinaire31$resultatBinaire32"


$calcul_adresse_reseau_BinaireSplit = $calcul_adresse_reseau_Binaire.Split(".")

$g = $calcul_adresse_reseau_BinaireSplit[0]
$h = $calcul_adresse_reseau_BinaireSplit[1]
$i = $calcul_adresse_reseau_BinaireSplit[2]
$j = $calcul_adresse_reseau_BinaireSplit[3]

# conversion en décimal
$g_Decimal = [convert]::ToInt32($g,2)
$h_Decimal = [convert]::ToInt32($h,2)
$i_Decimal = [convert]::ToInt32($i,2)
$j_Decimal = [convert]::ToInt32($j,2)

$AdresseIPReseau = "$g_Decimal.$h_Decimal.$i_Decimal.$j_Decimal"

# -------------------------------------------------------------------------
#Calcul du premier Host 

$PremierHostBinaire = "$resultatBinaire1$resultatBinaire2$resultatBinaire3$resultatBinaire4$resultatBinaire5$resultatBinaire6$resultatBinaire7$resultatBinaire8.$resultatBinaire9$resultatBinaire10$resultatBinaire11$resultatBinaire12$resultatBinaire13$resultatBinaire14$resultatBinaire15$resultatBinaire16.$resultatBinaire17$resultatBinaire18$resultatBinaire19$resultatBinaire20$resultatBinaire21$resultatBinaire22$resultatBinaire23$resultatBinaire24.$resultatBinaire25$resultatBinaire26$resultatBinaire27$resultatBinaire28$resultatBinaire29$resultatBinaire30$resultatBinaire31" + "1"

$PremierHostBinaireSplit = $PremierHostBinaire.Split(".")

$k = $PremierHostBinaireSplit[0]
$l = $PremierHostBinaireSplit[1]
$m = $PremierHostBinaireSplit[2]
$n = $PremierHostBinaireSplit[3]

# conversion en décimal
$k_Decimal = [convert]::ToInt32($k,2)
$l_Decimal = [convert]::ToInt32($l,2)
$m_Decimal = [convert]::ToInt32($m,2)
$n_Decimal = [convert]::ToInt32($n,2)


$AdresseIPPremierHost = "$k_Decimal.$l_Decimal.$m_Decimal.$n_Decimal"
#-------------------------------------------------------------------------------
# calcul de l'adresse de Broadcast

#Masque binaire sans les points
$compte0 = $Conversion_Masque -replace ("\.")

#calcul de l'index du dernier 1
$index1 = $Compte0.lastindexofany("1")

#avoir le nombre de bit à changer de 0 à 1
$nombre0 = 31 - $index1

#adresse de réseau binaire sans les points
$compte1 = $calcul_adresse_reseau_Binaire -replace ("\.")

#partie adresse broadcast a ne pas modifier
$Broadcast1_sans_point = $compte1.substring(0,$compte1.length -$nombre0)

#adresse de broadcast entiere sans les points ( ajout de 1 jusqu'a 32 caractères)
$Broadcast2_sans_point = $Broadcast1_sans_point.PadRight(32,'1')

# rajout des points à l'adresse de broadcast
$BroadcastBinaire = $Broadcast2_sans_point.ToString().Substring(0, 8) + "." + $Broadcast2_sans_point.ToString().Substring(8, 8) + "." + $Broadcast2_sans_point.ToString().Substring(16, 8) + "." + $Broadcast2_sans_point.ToString().Substring(24, 8) 

# conversion de l'adresse de broadcast en adresse IP

$BroadcastBinaireSplit = $BroadcastBinaire.Split(".")

$o = $BroadcastBinaireSplit[0]
$p = $BroadcastBinaireSplit[1]
$q = $BroadcastBinaireSplit[2]
$r = $BroadcastBinaireSplit[3]

# conversion en décimal
$o_Decimal = [convert]::ToInt32($o,2)
$p_Decimal = [convert]::ToInt32($p,2)
$q_Decimal = [convert]::ToInt32($q,2)
$r_Decimal = [convert]::ToInt32($r,2)

$AdresseIP_Broadcast = "$o_Decimal.$p_Decimal.$q_Decimal.$r_Decimal"
#--------------------------------------------------------------------------------
#Adresse du dernier host

$dernier_Host_Binaire = $BroadcastBinaire -replace (".$","0")

$dernier_Host_BinaireSplit = $dernier_Host_Binaire.Split(".")

$s = $dernier_Host_BinaireSplit[0]
$t = $dernier_Host_BinaireSplit[1]
$u = $dernier_Host_BinaireSplit[2]
$v = $dernier_Host_BinaireSplit[3]

# conversion en décimal
$s_Decimal = [convert]::ToInt32($s,2)
$t_Decimal = [convert]::ToInt32($t,2)
$u_Decimal = [convert]::ToInt32($u,2)
$v_Decimal = [convert]::ToInt32($v,2)

$AdresseIP_dernier_host = "$s_Decimal.$t_Decimal.$u_Decimal.$v_Decimal"

#--------------------------------------------------------------------------------------------
#Calcul du nombre d'hôtes
$NombreHote = ([math]::Pow(2,$nombre0)) - 2

#---------------------------------------------------------------------------------------------
#affichage dans le terminal


Write-Host "Adresse IP du Réseau               : $AdresseIPReseau" -ForegroundColor Magenta

write-host ""

Write-Host "Adresse IP du premier host         : $AdresseIPPremierHost" -ForegroundColor Blue

Write-Host ""

Write-Host "Adresse IP du dernier host         : $AdresseIP_dernier_host" -ForegroundColor Blue

Write-Host ""

write-host "Adresse IP de Broadcast            : $AdresseIP_Broadcast" -ForegroundColor Magenta

write-host ""
Write-Host "Hôtes Total du réseau              : $NombreHote" -ForegroundColor Cyan

write-host ""

}

# Fin de la fonction -------------------------------------------------------------------------------------------------------



  Do{
  
  Write-Host "################ MENU ##################"
  write-host “1. Scan réseau” -ForegroundColor Cyan
  write-host "2. Scan réseau + Scan des Ports ouverts" -ForegroundColor DarkCyan
  Write-Host "x. exit" -ForegroundColor Red
  Write-Host "########################################"
  Write-Host ""
  $choix = read-host “faire un choix”

  switch ($choix){

####################################################################################################
# “1. Scan réseau”
   
    1{
    
    
    #interface physique active
    $InterfaceUp = Get-NetAdapter | where {$_.status -like "Up" -and $_.Name -notlike "VMware*" -and $_.Name -notlike "Connexion*"} | select -ExpandProperty Name
    $MasqueCIDR = get-netipaddress | where {$_.interfaceAlias -eq $InterfaceUp -and $_.AddressFamily -eq "IPv4"} | select -ExpandProperty PrefixLength
    $Mac = Get-netadapter -Name $InterfaceUp | select -ExpandProperty MacAddress
    $DHCP = Get-NetIPInterface | where {$_.InterfaceAlias -eq $InterfaceUp -and $_.AddressFamily -eq "IPv4"} | select -ExpandProperty Dhcp
    $AdresseIPHost = Get-NetIPAddress | where {$_.interfaceAlias -eq $InterfaceUp -and $_.AddressFamily -eq "IPv4"} | select -ExpandProperty IPAddress

    #interface VPN
    $InterfaceUp_VPN = Get-NetAdapter | where {$_.status -like "Up" -and $_.Name -notlike "VMware*" -and $_.Name -like "Connexion au réseau local*"} | select -ExpandProperty Name
    $Interface_VPN_Status = Get-NetAdapter | where {$_.status -like "Up" -and $_.Name -notlike "VMware*" -and $_.Name -like "Connexion au réseau local*"} | select -ExpandProperty Status
    $MasqueCIDR_VPN = get-netipaddress | where {$_.interfaceAlias -eq $InterfaceUp_VPN -and $_.AddressFamily -eq "IPv4"} | select -ExpandProperty PrefixLength
    $Mac_VPN = Get-netadapter -Name $InterfaceUp_VPN | select -ExpandProperty MacAddress
    $DHCP_VPN = Get-NetIPInterface | where {$_.InterfaceAlias -eq $InterfaceUp_VPN -and $_.AddressFamily -eq "IPv4"} | select -ExpandProperty Dhcp
    $AdresseIP_VPN = Get-NetIPAddress | where {$_.interfaceAlias -eq $InterfaceUp_VPN -and $_.AddressFamily -eq "IPv4"} | select -ExpandProperty IPAddress


    if ($MasqueCIDR -eq 0)
    {
    $MasqueHost = "0.0.0.0"
    }

    if ($MasqueCIDR -eq 1)
    {
    $MasqueHost = "128.0.0.0"
    }
    
    if ($MasqueCIDR -eq 2)
    {
    $MasqueHost = "192.0.0.0"
    }
    
    if ($MasqueCIDR -eq 3)
    {
    $MasqueHost = "224.0.0.0"
    }
    
    if ($MasqueCIDR -eq 4)
    {
    $MasqueHost = "140.0.0.0"
    }
    
    if ($MasqueCIDR -eq 5)
    {
    $MasqueHost = "148.0.0.0"
    }
    
    if ($MasqueCIDR -eq 6)
    {
    $MasqueHost = "252.0.0.0"
    }
    
    if ($MasqueCIDR -eq 7)
    {
    $MasqueHost = "254.0.0.0"
    }
 
    if ($MasqueCIDR -eq 8)
    {
    $MasqueHost = "255.0.0.0"
    }

    if ($MasqueCIDR -eq 9)
    {
    $MasqueHost = "255.128.0.0"
    }

    if ($MasqueCIDR -eq 10)
    {
    $MasqueHost = "255.192.0.0"
    }

    if ($MasqueCIDR -eq 11)
    {
    $MasqueHost = "255.224.0.0"
    }

    if ($MasqueCIDR -eq 12)
    {
    $MasqueHost = "255.240.0.0"
    }

    if ($MasqueCIDR -eq 13)
    {
    $MasqueHost = "255.248.0.0"
    }

    if ($MasqueCIDR -eq 14)
    {
    $MasqueHost = "255.252.0.0"
    }

    if ($MasqueCIDR -eq 15)
    {
    $MasqueHost = "255.254.0.0"
    }

    if ($MasqueCIDR -eq 16)
    {
    $MasqueHost = "255.255.0.0"
    }

    if ($MasqueCIDR -eq 17)
    {
    $MasqueHost = "255.255.128.0"
    }

    if ($MasqueCIDR -eq 18)
    {
    $MasqueHost = "255.255.192.0"
    }

    if ($MasqueCIDR -eq 19)
    {
    $MasqueHost = "255.255.224.0"
    }

    if ($MasqueCIDR -eq 20)
    {
    $MasqueHost = "255.255.240.0"
    }

    if ($MasqueCIDR -eq 21)
    {
    $MasqueHost = "255.255.248.0"
    }

    if ($MasqueCIDR -eq 22)
    {
    $MasqueHost = "255.255.252.0"
    }

    if ($MasqueCIDR -eq 23)
    {
    $MasqueHost = "255.255.254.0"
    }

    if ($MasqueCIDR -eq 24)
    {
    $MasqueHost = "255.255.255.0"
    }

    if ($MasqueCIDR -eq 25)
    {
    $MasqueHost = "255.255.255.128"
    }

    if ($MasqueCIDR -eq 26)
    {
    $MasqueHost = "255.255.255.192"
    }


    if ($MasqueCIDR -eq 27)
    {
    $MasqueHost = "255.255.255.224"
    }

    if ($MasqueCIDR -eq 28)
    {
    $MasqueHost = "255.255.255.240"
    }

    if ($MasqueCIDR -eq 29)
    {
    $MasqueHost = "255.255.255.248"
    }

    if ($MasqueCIDR -eq 30)
    {
    $MasqueHost = "255.255.255.252"
    }

    if ($MasqueCIDR -eq 31)
    {
    $MasqueHost = "255.255.255.254"
    }

    if ($MasqueCIDR -eq 32)
    {
    $MasqueHost = "255.255.255.255"
    }


# ------------------------------------------------------------------


if ($MasqueCIDR_VPN -eq 0)
    {
    $Masque_VPN = "0.0.0.0"
    }

    if ($MasqueCIDR_VPN -eq 1)
    {
    $Masque_VPN = "128.0.0.0"
    }
    
    if ($MasqueCIDR_VPN -eq 2)
    {
    $Masque_VPN = "192.0.0.0"
    }
    
    if ($MasqueCIDR_VPN -eq 3)
    {
    $Masque_VPN = "224.0.0.0"
    }
    
    if ($MasqueCIDR_VPN -eq 4)
    {
    $Masque_VPN = "140.0.0.0"
    }
    
    if ($MasqueCIDR_VPN -eq 5)
    {
    $Masque_VPN = "148.0.0.0"
    }
    
    if ($MasqueCIDR_VPN -eq 6)
    {
    $Masque_VPN = "252.0.0.0"
    }
    
    if ($MasqueCIDR_VPN -eq 7)
    {
    $Masque_VPN = "254.0.0.0"
    }
 
    if ($MasqueCIDR_VPN -eq 8)
    {
    $Masque_VPN = "255.0.0.0"
    }

    if ($MasqueCIDR_VPN -eq 9)
    {
    $Masque_VPN = "255.128.0.0"
    }

    if ($MasqueCIDR_VPN -eq 10)
    {
    $Masque_VPN = "255.192.0.0"
    }

    if ($MasqueCIDR_VPN -eq 11)
    {
    $Masque_VPN = "255.224.0.0"
    }

    if ($MasqueCIDR_VPN -eq 12)
    {
    $Masque_VPN = "255.240.0.0"
    }

    if ($MasqueCIDR_VPN -eq 13)
    {
    $Masque_VPN = "255.248.0.0"
    }

    if ($MasqueCIDR_VPN -eq 14)
    {
    $Masque_VPN = "255.252.0.0"
    }

    if ($MasqueCIDR_VPN -eq 15)
    {
    $Masque_VPN = "255.254.0.0"
    }

    if ($MasqueCIDR_VPN -eq 16)
    {
    $Masque_VPN = "255.255.0.0"
    }

    if ($MasqueCIDR_VPN -eq 17)
    {
    $Masque_VPN = "255.255.128.0"
    }

    if ($MasqueCIDR_VPN -eq 18)
    {
    $Masque_VPN = "255.255.192.0"
    }

    if ($MasqueCIDR_VPN -eq 19)
    {
    $Masque_VPN = "255.255.224.0"
    }

    if ($MasqueCIDR_VPN -eq 20)
    {
    $Masque_VPN = "255.255.240.0"
    }

    if ($MasqueCIDR_VPN -eq 21)
    {
    $Masque_VPN = "255.255.248.0"
    }

    if ($MasqueCIDR_VPN -eq 22)
    {
    $Masque_VPN = "255.255.252.0"
    }

    if ($MasqueCIDR_VPN -eq 23)
    {
    $Masque_VPN = "255.255.254.0"
    }

    if ($MasqueCIDR_VPN -eq 24)
    {
    $Masque_VPN = "255.255.255.0"
    }

    if ($MasqueCIDR_VPN -eq 25)
    {
    $Masque_VPN = "255.255.255.128"
    }

    if ($MasqueCIDR_VPN -eq 26)
    {
    $Masque_VPN = "255.255.255.192"
    }


    if ($MasqueCIDR_VPN -eq 27)
    {
    $Masque_VPN = "255.255.255.224"
    }

    if ($MasqueCIDR_VPN -eq 28)
    {
    $Masque_VPN = "255.255.255.240"
    }

    if ($MasqueCIDR_VPN -eq 29)
    {
    $Masque_VPN = "255.255.255.248"
    }

    if ($MasqueCIDR_VPN -eq 30)
    {
    $Masque_VPN = "255.255.255.252"
    }

    if ($MasqueCIDR_VPN -eq 31)
    {
    $Masque_VPN = "255.255.255.254"
    }

    if ($MasqueCIDR_VPN -eq 32)
    {
    $Masque_VPN = "255.255.255.255"
    }


    # ----------------------------------------------------------------

    Write-Host ""

    write-Host "Configuration IP actuelle de la machine :" -ForegroundColor Green

    write-host ""


    Get-NetIPConfiguration | where InterfaceAlias -eq $InterfaceUp


    write-host "Masque sous-réseaux  : $MasqueHost / CIDR: $MasqueCIDR"

    
    Write-Host "Adresse MAC          : $Mac"

    
    Write-Host "DHCP                 : $DHCP"

    Write-Host ""
    Write-Host ""

    Calcul_Reseaux $AdresseIPHost $MasqueHost

    Write-Host "-----------------------------------------------------------------------"
    Write-Host "-----------------------------------------------------------------------"
    Write-Host "-----------------------------------------------------------------------"


    if ($interface_VPN_Status -like "Up")
    {


    write-Host "Configuration IP de la connexion VPN :" -ForegroundColor Green

    write-host ""


    Get-NetIPConfiguration | where InterfaceAlias -eq $InterfaceUp_VPN


    write-host "Masque sous-réseaux  : $Masque_VPN / CIDR: $MasqueCIDR_VPN"

    
    Write-Host "Adresse MAC          : $Mac_VPN"

    
    Write-Host "DHCP                 : $DHCP_VPN"

    Write-Host ""
    write-host ""

    Calcul_Reseaux $AdresseIP_VPN $Masque_VPN
    }





# ------------------------------------------------------------------------------------------------------
# ------------------------------------------------------------------------------------------------------
Write-Host ""
write-host "#############################################"
write-host "###############  SCAN RESEAU  ###############"
write-host "#############################################"
write-host ""
write-host "Afin de ne cibler qu'une seule adresse IP, vous pouvez laisser le champ 'Adresse IP de fin' vide" -ForegroundColor Cyan
Write-Host ""

Do{

$AdresseDepart = Read-host "Entrez l'adresse IP de départ"
$AdresseFin = Read-Host "Entrez l'adresse IP de Fin"
write-host ""
Write-Host "#############################################"
Write-Host "#############################################"
Write-Host ""


if ($AdresseDepart -notmatch "^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$") 
{


write-host "Veuillez indiquer au moins une Adresse IP de Départ valide" -ForegroundColor Magenta

write-host ""

pause

Write-Host ""

}


}

until ((($AdresseDepart -match "^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$") -and ($AdresseFin -match "^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$")) -or (($AdresseDepart -match "^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$") -and ($AdresseFin -like $null)))


if ($AdresseFin -like $null)
{
$AdresseFin = $AdresseDepart
}

Write-Host "############### Début du scan ###############"
"############## Début du Scan ##############" >> Resultat_Scan.txt
Get-Date >> Resultat_Scan.txt
"# Adresse IP de départ : $AdresseDepart" >> Resultat_Scan.txt
"# Adresse IP de Fin    : $AdresseFin" >> Resultat_Scan.txt
" " >> Resultat_Scan.txt
" " >> Resultat_Scan.txt


$AdresseDepartSplit = $AdresseDepart.Split(".")
$AdresseFinSplit = $AdresseFin.Split(".")


$a = $AdresseDepartSplit[0]
$b = $AdresseDepartSplit[1]
$c = $AdresseDepartSplit[2]
$d = $AdresseDepartSplit[3]



$a_int = [int]$a
$b_int = [int]$b
$c_int = [int]$c
$d_int = [int]$d



$valeur = $a..255 | % {"$($_)"}

Foreach ($object1 in $valeur)
{

For ($x=$b_int;$x -lt 256;$x++)
{

$Adresse2octets = "$object1.$x"



Foreach ($object2 in $Adresse2octets)
{

For ($y=$c_int;$y -lt 256;$y++)
{
$Adresse3octets = "$object2.$y"


Foreach ($object3 in $Adresse3octets)
{

For ($z=$d_int;$z -lt 256;$z++)
{
$AdresseIP = "$object3.$z"


$NomHote = Resolve-DnsName $AdresseIP -ErrorAction SilentlyContinue | select -ExpandProperty NameHost
#$ScanBool = [bool] (Test-Connection $AdresseIP -count 1 -ErrorAction SilentlyContinue)
$ScanBool = Test-Connection -BufferSize 32 -count 1 -comp $AdresseIP -quiet


if (($ScanBool -eq $true) -and ($AdresseIP -ne $AdresseFin))
{
write-Host "la machine $AdresseIP (nom d'hôte : $NomHote) a bien répondu au ping" -ForegroundColor Green

"@@ la machine $AdresseIP - $NomHote a bien répondu au ping" >> Resultat_Scan.txt

}

if (($ScanBool -eq $false) -and ($AdresseIP -ne $AdresseFin))
{
Write-Host "la machine $AdresseIP n'est pas joignable" -ForegroundColor Red

"~~ la machine $AdresseIP n'est pas joignable" >> Resultat_Scan.txt
}

if (($ScanBool -eq $true) -and ($AdresseIP -eq $AdresseFin))
{


Write-Host "la machine $AdresseIP (nom d'hôte : $NomHote) a bien répondu au ping" -ForegroundColor Green

"@@ la machine $AdresseIP - $NomHote a bien répondu au ping" >> Resultat_Scan.txt

Write-Host "################ Fin du Scan ################" -ForegroundColor Yellow

" " >> Resultat_Scan.txt

"################ Fin du Scan ################" >> Resultat_Scan.txt

" " >> Resultat_Scan.txt

pause

Cls



}

if (($ScanBool -eq $false) -and ($AdresseIP -eq $AdresseFin))
{

Write-Host "la machine $AdresseIP n'est pas joignable" -ForegroundColor Red

"~~ la machine $AdresseIP n'est pas joignable" >> Resultat_Scan.txt

Write-Host "################ Fin du Scan ################" -ForegroundColor Yellow

" " >> Resultat_Scan.txt

"################ Fin du Scan ################" >> Resultat_Scan.txt
write-host " " >> Resultat_Scan.txt
Get-Date >> Resultat_Scan.txt

" " >> Resultat_Scan.txt


pause

Cls

break


}
if ($AdresseIP -eq $AdresseFin) {break}
}
if ($AdresseIP -eq $AdresseFin) {break}
}
if ($AdresseIP -eq $AdresseFin) {break}
}
if ($AdresseIP -eq $AdresseFin) {break}
}
if ($AdresseIP -eq $AdresseFin) {break}
}
if ($AdresseIP -eq $AdresseFin) {break}
}
if ($AdresseIP -eq $AdresseFin) {break}
}



#############################################################################################################
# "2. Scan réseau + Scan des Ports ouverts"
    
    2{



    #interface physique active
    $InterfaceUp = Get-NetAdapter | where {$_.status -like "Up" -and $_.Name -notlike "VMware*" -and $_.Name -notlike "Connexion*"} | select -ExpandProperty Name
    $MasqueCIDR = get-netipaddress | where {$_.interfaceAlias -eq $InterfaceUp -and $_.AddressFamily -eq "IPv4"} | select -ExpandProperty PrefixLength
    $Mac = Get-netadapter -Name $InterfaceUp | select -ExpandProperty MacAddress
    $DHCP = Get-NetIPInterface | where {$_.InterfaceAlias -eq $InterfaceUp -and $_.AddressFamily -eq "IPv4"} | select -ExpandProperty Dhcp
    $AdresseIPHost = Get-NetIPAddress | where {$_.interfaceAlias -eq $InterfaceUp -and $_.AddressFamily -eq "IPv4"} | select -ExpandProperty IPAddress

    #interface VPN
    $InterfaceUp_VPN = Get-NetAdapter | where {$_.status -like "Up" -and $_.Name -notlike "VMware*" -and $_.Name -like "Connexion au réseau local*"} | select -ExpandProperty Name
    $Interface_VPN_Status = Get-NetAdapter | where {$_.status -like "Up" -and $_.Name -notlike "VMware*" -and $_.Name -like "Connexion au réseau local*"} | select -ExpandProperty Status
    $MasqueCIDR_VPN = get-netipaddress | where {$_.interfaceAlias -eq $InterfaceUp_VPN -and $_.AddressFamily -eq "IPv4"} | select -ExpandProperty PrefixLength
    $Mac_VPN = Get-netadapter -Name $InterfaceUp_VPN | select -ExpandProperty MacAddress
    $DHCP_VPN = Get-NetIPInterface | where {$_.InterfaceAlias -eq $InterfaceUp_VPN -and $_.AddressFamily -eq "IPv4"} | select -ExpandProperty Dhcp
    $AdresseIP_VPN = Get-NetIPAddress | where {$_.interfaceAlias -eq $InterfaceUp_VPN -and $_.AddressFamily -eq "IPv4"} | select -ExpandProperty IPAddress


    if ($MasqueCIDR -eq 0)
    {
    $MasqueHost = "0.0.0.0"
    }

    if ($MasqueCIDR -eq 1)
    {
    $MasqueHost = "128.0.0.0"
    }
    
    if ($MasqueCIDR -eq 2)
    {
    $MasqueHost = "192.0.0.0"
    }
    
    if ($MasqueCIDR -eq 3)
    {
    $MasqueHost = "224.0.0.0"
    }
    
    if ($MasqueCIDR -eq 4)
    {
    $MasqueHost = "140.0.0.0"
    }
    
    if ($MasqueCIDR -eq 5)
    {
    $MasqueHost = "148.0.0.0"
    }
    
    if ($MasqueCIDR -eq 6)
    {
    $MasqueHost = "252.0.0.0"
    }
    
    if ($MasqueCIDR -eq 7)
    {
    $MasqueHost = "254.0.0.0"
    }
 
    if ($MasqueCIDR -eq 8)
    {
    $MasqueHost = "255.0.0.0"
    }

    if ($MasqueCIDR -eq 9)
    {
    $MasqueHost = "255.128.0.0"
    }

    if ($MasqueCIDR -eq 10)
    {
    $MasqueHost = "255.192.0.0"
    }

    if ($MasqueCIDR -eq 11)
    {
    $MasqueHost = "255.224.0.0"
    }

    if ($MasqueCIDR -eq 12)
    {
    $MasqueHost = "255.240.0.0"
    }

    if ($MasqueCIDR -eq 13)
    {
    $MasqueHost = "255.248.0.0"
    }

    if ($MasqueCIDR -eq 14)
    {
    $MasqueHost = "255.252.0.0"
    }

    if ($MasqueCIDR -eq 15)
    {
    $MasqueHost = "255.254.0.0"
    }

    if ($MasqueCIDR -eq 16)
    {
    $MasqueHost = "255.255.0.0"
    }

    if ($MasqueCIDR -eq 17)
    {
    $MasqueHost = "255.255.128.0"
    }

    if ($MasqueCIDR -eq 18)
    {
    $MasqueHost = "255.255.192.0"
    }

    if ($MasqueCIDR -eq 19)
    {
    $MasqueHost = "255.255.224.0"
    }

    if ($MasqueCIDR -eq 20)
    {
    $MasqueHost = "255.255.240.0"
    }

    if ($MasqueCIDR -eq 21)
    {
    $MasqueHost = "255.255.248.0"
    }

    if ($MasqueCIDR -eq 22)
    {
    $MasqueHost = "255.255.252.0"
    }

    if ($MasqueCIDR -eq 23)
    {
    $MasqueHost = "255.255.254.0"
    }

    if ($MasqueCIDR -eq 24)
    {
    $MasqueHost = "255.255.255.0"
    }

    if ($MasqueCIDR -eq 25)
    {
    $MasqueHost = "255.255.255.128"
    }

    if ($MasqueCIDR -eq 26)
    {
    $MasqueHost = "255.255.255.192"
    }


    if ($MasqueCIDR -eq 27)
    {
    $MasqueHost = "255.255.255.224"
    }

    if ($MasqueCIDR -eq 28)
    {
    $MasqueHost = "255.255.255.240"
    }

    if ($MasqueCIDR -eq 29)
    {
    $MasqueHost = "255.255.255.248"
    }

    if ($MasqueCIDR -eq 30)
    {
    $MasqueHost = "255.255.255.252"
    }

    if ($MasqueCIDR -eq 31)
    {
    $MasqueHost = "255.255.255.254"
    }

    if ($MasqueCIDR -eq 32)
    {
    $MasqueHost = "255.255.255.255"
    }


# ------------------------------------------------------------------


if ($MasqueCIDR_VPN -eq 0)
    {
    $Masque_VPN = "0.0.0.0"
    }

    if ($MasqueCIDR_VPN -eq 1)
    {
    $Masque_VPN = "128.0.0.0"
    }
    
    if ($MasqueCIDR_VPN -eq 2)
    {
    $Masque_VPN = "192.0.0.0"
    }
    
    if ($MasqueCIDR_VPN -eq 3)
    {
    $Masque_VPN = "224.0.0.0"
    }
    
    if ($MasqueCIDR_VPN -eq 4)
    {
    $Masque_VPN = "140.0.0.0"
    }
    
    if ($MasqueCIDR_VPN -eq 5)
    {
    $Masque_VPN = "148.0.0.0"
    }
    
    if ($MasqueCIDR_VPN -eq 6)
    {
    $Masque_VPN = "252.0.0.0"
    }
    
    if ($MasqueCIDR_VPN -eq 7)
    {
    $Masque_VPN = "254.0.0.0"
    }
 
    if ($MasqueCIDR_VPN -eq 8)
    {
    $Masque_VPN = "255.0.0.0"
    }

    if ($MasqueCIDR_VPN -eq 9)
    {
    $Masque_VPN = "255.128.0.0"
    }

    if ($MasqueCIDR_VPN -eq 10)
    {
    $Masque_VPN = "255.192.0.0"
    }

    if ($MasqueCIDR_VPN -eq 11)
    {
    $Masque_VPN = "255.224.0.0"
    }

    if ($MasqueCIDR_VPN -eq 12)
    {
    $Masque_VPN = "255.240.0.0"
    }

    if ($MasqueCIDR_VPN -eq 13)
    {
    $Masque_VPN = "255.248.0.0"
    }

    if ($MasqueCIDR_VPN -eq 14)
    {
    $Masque_VPN = "255.252.0.0"
    }

    if ($MasqueCIDR_VPN -eq 15)
    {
    $Masque_VPN = "255.254.0.0"
    }

    if ($MasqueCIDR_VPN -eq 16)
    {
    $Masque_VPN = "255.255.0.0"
    }

    if ($MasqueCIDR_VPN -eq 17)
    {
    $Masque_VPN = "255.255.128.0"
    }

    if ($MasqueCIDR_VPN -eq 18)
    {
    $Masque_VPN = "255.255.192.0"
    }

    if ($MasqueCIDR_VPN -eq 19)
    {
    $Masque_VPN = "255.255.224.0"
    }

    if ($MasqueCIDR_VPN -eq 20)
    {
    $Masque_VPN = "255.255.240.0"
    }

    if ($MasqueCIDR_VPN -eq 21)
    {
    $Masque_VPN = "255.255.248.0"
    }

    if ($MasqueCIDR_VPN -eq 22)
    {
    $Masque_VPN = "255.255.252.0"
    }

    if ($MasqueCIDR_VPN -eq 23)
    {
    $Masque_VPN = "255.255.254.0"
    }

    if ($MasqueCIDR_VPN -eq 24)
    {
    $Masque_VPN = "255.255.255.0"
    }

    if ($MasqueCIDR_VPN -eq 25)
    {
    $Masque_VPN = "255.255.255.128"
    }

    if ($MasqueCIDR_VPN -eq 26)
    {
    $Masque_VPN = "255.255.255.192"
    }


    if ($MasqueCIDR_VPN -eq 27)
    {
    $Masque_VPN = "255.255.255.224"
    }

    if ($MasqueCIDR_VPN -eq 28)
    {
    $Masque_VPN = "255.255.255.240"
    }

    if ($MasqueCIDR_VPN -eq 29)
    {
    $Masque_VPN = "255.255.255.248"
    }

    if ($MasqueCIDR_VPN -eq 30)
    {
    $Masque_VPN = "255.255.255.252"
    }

    if ($MasqueCIDR_VPN -eq 31)
    {
    $Masque_VPN = "255.255.255.254"
    }

    if ($MasqueCIDR_VPN -eq 32)
    {
    $Masque_VPN = "255.255.255.255"
    }


    # ----------------------------------------------------------------

    Write-Host ""

    write-Host "Configuration IP actuelle de la machine :" -ForegroundColor Green

    write-host ""


    Get-NetIPConfiguration | where InterfaceAlias -eq $InterfaceUp


    write-host "Masque sous-réseaux  : $MasqueHost / CIDR: $MasqueCIDR"

    
    Write-Host "Adresse MAC          : $Mac"

    
    Write-Host "DHCP                 : $DHCP"

    Write-Host ""
    Write-Host ""

    Calcul_Reseaux $AdresseIPHost $MasqueHost

    Write-Host "-----------------------------------------------------------------------"
    Write-Host "-----------------------------------------------------------------------"
    Write-Host "-----------------------------------------------------------------------"
    write-host ""


    if ($interface_VPN_Status -like "Up")
    {


    write-Host "Configuration IP de la connexion VPN :" -ForegroundColor Green

    write-host ""


    Get-NetIPConfiguration | where InterfaceAlias -eq $InterfaceUp_VPN


    write-host "Masque sous-réseaux  : $Masque_VPN / CIDR: $MasqueCIDR_VPN"

    
    Write-Host "Adresse MAC          : $Mac_VPN"

    
    Write-Host "DHCP                 : $DHCP_VPN"

    Write-Host ""
    write-host ""

    Calcul_Reseaux $AdresseIP_VPN $Masque_VPN
    }

write-host ""


write-host "##########################################################"
write-host "###############  SCAN RESEAU + SCAN PORTS  ###############"
write-host "##########################################################"
write-host ""
Write-Host "Ports testés :"
write-host "21 (FTP)"
write-host "22 (SSH)"
write-host "23 (Telnet)"
write-host "53 (DNS)"
write-host "69 (TFTP)"
write-host "80 (HTTP)"
write-host "139 (Service NetBIOS - partage de ressources)"
write-host "161 (SNMP)"
write-host "443 (HTTPS)"
write-host "445 (CIFS-SMB,Samba - partage de ressources)"
write-host "548 (AFP - partage de fichiers Apple)"
write-host "1433 (Microsoft SQL Server)"
write-host "3306 (MySQL)"
write-host "3389 (RDP)"
Write-Host "5900 (VNC Server)"
Write-Host ""
write-host "------------------------------------------------------------------------------------------------"
write-host ""
write-host "Afin de ne cibler qu'une seule adresse IP, vous pouvez laisser le champ 'Adresse IP de fin' vide" -ForegroundColor Cyan
write-host ""


Do{

$AdresseDepart = Read-host "Adresse IP de départ"
$AdresseFin = Read-Host "Adresse IP de Fin"
write-host " "

write-host " "


if ($AdresseDepart -notmatch "^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$") 
{


write-host "Veuillez indiquer au moins une Adresse IP de Départ valide" -ForegroundColor Magenta

write-host ""

pause

Write-Host ""

}


}

until ((($AdresseDepart -match "^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$") -and ($AdresseFin -match "^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$")) -or (($AdresseDepart -match "^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$") -and ($AdresseFin -like $null)))


if ($AdresseFin -like $null)
{
$AdresseFin = $AdresseDepart
}


write-host "############## Début du Scan réseau + scan ports ##############"
Write-Host ""

$location = Get-Location | select -ExpandProperty Path

$AdresseDepartSplit = $AdresseDepart.Split(".")
$AdresseFinSplit = $AdresseFin.Split(".")


$a = $AdresseDepartSplit[0]
$b = $AdresseDepartSplit[1]
$c = $AdresseDepartSplit[2]
$d = $AdresseDepartSplit[3]



$a_int = [int]$a
$b_int = [int]$b
$c_int = [int]$c
$d_int = [int]$d



$valeur = $a..255 | % {"$($_)"}

Foreach ($object1 in $valeur)
{

For ($x=$b_int;$x -lt 256;$x++)
{

$Adresse2octets = "$object1.$x"



Foreach ($object2 in $Adresse2octets)
{

For ($y=$c_int;$y -lt 256;$y++)
{
$Adresse3octets = "$object2.$y"


Foreach ($object3 in $Adresse3octets)
{

For ($z=$d_int;$z -lt 256;$z++)
{
$AdresseIP = "$object3.$z"

$NomHote = Resolve-DnsName $AdresseIP -ErrorAction SilentlyContinue | select -ExpandProperty NameHost
$ScanBool = [bool] (Test-Connection -Buffersize 32 $AdresseIP -count 1 -ErrorAction SilentlyContinue)
#$ScanBool = Test-Connection -BufferSize 32 -count 1 -comp $AdresseIP -quiet

if (($ScanBool -eq $true) -and ($AdresseIP -ne $AdresseFin))
{


$portrange = 21,22,23,53,69,80,139,161,443,445,548,1433,3306,3389,5900
#$portrange = 1..65535

$timeout_ms = 5
 
 
        Write-Host "$AdresseIP est connecté... vérification des ports ouverts..." -ForegroundColor Green
 
        foreach ($port in $portrange)
        {
            $ErrorActionPreference = 'SilentlyContinue'
            $socket = new-object System.Net.Sockets.TcpClient
            $connect = $socket.BeginConnect($AdresseIP, $port, $null, $null)
            $tryconnect = Measure-Command { $success = $connect.AsyncWaitHandle.WaitOne($timeout_ms, $true) } | % totalmilliseconds
            $tryconnect | Out-Null
 
            if ($socket.Connected)
            {
                "$AdresseIP is listening on port $port (Response Time: $tryconnect ms)"
                $socket.Close()
                $socket.Dispose()
                $socket = $null
            }
 
            $ErrorActionPreference = 'Continue'
        }

}

if (($ScanBool -eq $false) -and ($AdresseIP -ne $AdresseFin))
{
write-host "$AdresseIP n'est pas joignable" -ForegroundColor Red
}


if (($ScanBool -eq $true) -and ($AdresseIP -eq $AdresseFin))
{


$portrange = 21,22,23,53,69,80,139,161,443,445,548,1433,3306,3389,5900
#$portrange = 1..65535

$timeout_ms = 5
 
 
        Write-Host "$AdresseIP est connecté... vérification des ports ouverts..." -ForegroundColor Green
 
        foreach ($port in $portrange)
        {
            $ErrorActionPreference = 'SilentlyContinue'
            $socket = new-object System.Net.Sockets.TcpClient
            $connect = $socket.BeginConnect($AdresseIP, $port, $null, $null)
            $tryconnect = Measure-Command { $success = $connect.AsyncWaitHandle.WaitOne($timeout_ms, $true) } | % totalmilliseconds
            $tryconnect | Out-Null
 
            if ($socket.Connected)
            {
                "$AdresseIP is listening on port $port (Response Time: $tryconnect ms)"
                $socket.Close()
                $socket.Dispose()
                $socket = $null
            }
 
            $ErrorActionPreference = 'Continue'
        }


write-Host "###### Fin du scan ###### Plage IP scannée : $AdresseDepart --> $AdresseFin" -ForegroundColor Yellow


pause

Cls

break



}


if (($ScanBool -eq $false) -and ($AdresseIP -eq $AdresseFin))
{

write-host "$AdresseIP n'est pas joignable" -ForegroundColor Red

write-Host "###### Fin du scan ###### Plage IP scannée : $AdresseDepart --> $AdresseFin" -ForegroundColor Yellow

pause

Cls

break

}
if ($AdresseIP -eq $AdresseFin) {break}
}
if ($AdresseIP -eq $AdresseFin) {break}
}
if ($AdresseIP -eq $AdresseFin) {break}
}
if ($AdresseIP -eq $AdresseFin) {break}
}
if ($AdresseIP -eq $AdresseFin) {break}
}
if ($AdresseIP -eq $AdresseFin) {break}
}
if ($AdresseIP -eq $AdresseFin) {break} 
}



#####################################################################################
# "x. exit"

    x{
    exit
    }

}
}



    until ($choix -eq "x")

    exit

   
