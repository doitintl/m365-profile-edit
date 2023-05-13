# m365-profile-edit-tool

Allow user to change his mobile phone and city in profile

Before using, change `app.secret_key` (line 8) in app.py to yours.

## Command to build docker image:
```
docker build --pull --rm -f "Dockerfile" -t yourimagetag:latest "."
```

## Command to run docker image with variables needed:
```
docker run -p 50000:50000 -e CLIENT_ID="<your app client id>" -e CLIENT_SECRET="<your app secret>" -e TENANT_NAME="<your tenant name or id>" yourimagetag:latest
```