from app import create_app

app = create_app()

if __name__ == "__main__":
    # Strictly bind to localhost (127.0.0.1) so the assessment platform is never exposed publicly
    app.run(host="127.0.0.1", port=5000, debug=True)
