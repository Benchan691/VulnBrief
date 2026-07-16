from core.application import create_app


app = create_app()

if __name__ == '__main__':
    app.run(ssl_context=('cert.pem', 'key.pem'), debug=False, host='0.0.0.0', port=9100)
