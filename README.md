sc-jwt-security
Ce module a pour but de vérifier la présence et la validité du jeton jwt dans le hearder des requêtes de l'ensemble des modules back du projet ITBoost.

Prerequisites (The following tools must be installed in your workstation)
Java 8
Tomcat 8
Maven 3
IDE (Eclipse, IntelliJ, ...)
Git
clone of projet
git clone ssh://git@p1-gaas-git01.cplus:7999/itb/sc-jwt-security.git

change branch
git checkout develop

change the directory
sc-jwt-security

check the build project
mvn clean install

Utilisation
Pour l'utiliser, il faudrait ajouter la dépendence du projet sc-jwt-security dans votre pom.xml et importer son fichier de configation java en ajoutant l'annotation @Import({JwtMvcConfig.class}) dans votre fichier de conf java.
Le module étant déployer nexus, le build maven ira le télécharger sous nexus.