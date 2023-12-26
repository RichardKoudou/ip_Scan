# ip_Scan
Projet_cours_interface_web
Pour installer ip_scan, veuillez télécharger le code en fichier .zip ou cloner le repository puis dans votre git bash :
- git clone + url du repository
- git pull (afin de récupérer la toute dernière version)
- Importez le fichier dans votre IDE

Pour commencer à utiliser ip_scan, vous devez installer :
- scapy (pip install scapy)
- flask (pip install Flask ou pip3 install Flask selon la version de python que vous utilisez)
- Nmap (pip install python-nmap)
  
Une fois les installations faites, vous pouvez lancer l'application avec la commande :
- cd src 
- Python app.py dans votre terminal.
  
Ouvrez votre navigateur, suivez les instructions afin de réaliser le scan adapté à votre besoin.
Vous avez plusieurs types de scans (TCP, UDP, etc...)
NB: Les scans UDP peuvent prendre beaucoup de temps.

Le bouton "save result" vous permet de stocker les informations trouvées dans une mémoire tampon. A chaque rafraichissement de la page, ces données sont effacées.
Pour enregistrer les informations trouvées de façon permanente, veuillez les télécharger via le bouton "download". 

