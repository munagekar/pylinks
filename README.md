# Running on Production

- Pipenv + Pyenv + HTTPS + Letsencrypt
```shell script
sudo source .env
sudo env "PATH=$PATH VIRTUAL_ENV=$VIRTUAL_ENV" pipenv run uvicorn pylinks.app:app --port 443 --host 0.0.0.0 --ssl-keyfile=$CERT_DIR/privkey.pem --ssl-certfile=$CERT_DIR/cert.pem
```