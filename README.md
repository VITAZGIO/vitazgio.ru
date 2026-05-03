# vitazgio.ru
Это панель выскакивающая при домене vitazgio.ru. Тут будут вкладки моих доменов и шпор.



cd C:\TRASH\NextCloud\Сервер\Programs\vitazgio.ru
git add .; git commit -m "BAZA-FINAL"; git push


если упадет то 
cd /opt/sites/vitazgio.ru

git fetch origin
git reset --hard origin/main
docker compose up -d --build
docker logs vitazgio-site
