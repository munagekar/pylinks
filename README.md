# Running on Production

- Pipenv + Pyenv + HTTPS + Letsencrypt
```shell script
source .env
sudo env "PATH=$PATH VIRTUAL_ENV=$VIRTUAL_ENV" pipenv run uvicorn pylinks.app:app --port 443 --host 0.0.0.0 --ssl-keyfile=$CERT_DIR/privkey.pem --ssl-certfile=$CERT_DIR/fullchain.pem
```


# Testing on Localhost
- brew install mkcert
- mkcert -install
- cd data
- mkcert localhost.com localhost 127.0.0.1