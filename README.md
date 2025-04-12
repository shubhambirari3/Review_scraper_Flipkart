# Review Scrapper 

## About the Project

The **Review Scrapper** is a Flask-based application designed to scrape reviews from Flipkart.com and provide secure access to the data using session-based authentication. It combines Flask for web development, BeautifulSoup for scraping, and SQLite for data storage.

## Features

- **Flask Framework**: Lightweight web application development.
- **Review Scraping**: Extracts reviews from Flipkart using web scraping techniques.
- **Session-Based Authentication**: Secure user access with Flask sessions and password hashing.
- **User Management**: Supports user registration and login.
- **Data Storage**: Stores scraped reviews in a SQLite database.
- **Scalable Design**: Handles moderate data volumes efficiently.

## Flask: How Data is Scraped

The application uses Flask to handle HTTP requests and manage the scraping process. Here's how the data scraping works:

1. **Scraping Libraries**: The project uses libraries like `BeautifulSoup` and `requests` to scrape reviews from target platforms.
2. **Endpoints**: Flask routes are defined to trigger the scraping process. For example:
   - `/scrape`: Initiates the scraping process for a specific platform.
3. **Data Storage**: Scraped data is stored in a database (e.g., MongoDB or PostgreSQL) for easy retrieval and analysis.
4. **Error Handling**: Flask handles errors gracefully, ensuring the application remains robust during scraping.

`

## Authentication

This project uses **session-based authentication**:
- **Mechanism**: User IDs are stored in Flask’s secure session cookies after login.
- **Security**: Passwords are hashed using `werkzeug.security`, and sessions are protected with a secret key.
- **Implementation**: Custom user loading via a `before_request` hook ensures authenticated access to protected routes.

*Note*: While `Flask-JWT-Extended` is included for potential future enhancements (e.g., API endpoints with JWT), the current implementation relies solely on session-based authentication.



## Installation

Follow these steps to set up the project on your local machine:

1. Clone the repository:
   ```bash
   git clone https://github.com/shubhambirari3/review_scrapper.git
   cd review_scrapper
   ```

2. Create a virtual environment and activate it:
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   - generate token 
   - Create a `.env` file in the root directory.
   - Add the following variables:
     ```
     FLASK_APP=app.py
     FLASK_ENV=development
     JWT_SECRET_KEY=your_jwt_secret
     DATABASE_URL=your_database_url
     ```

5. Run the application:
   ```bash
    python app.py
   ```

## Setup Instructions

1. **Prerequisites**:
   - create virtual env for this project 
   - install all dependencies requirements.txt
   - Python 3.8 or higher
   - Flask and required libraries (install via `requirements.txt`)
   

2. **Environment Configuration**:
   - Ensure the `.env` file is properly configured with your database URL and JWT secret.

3. **Running the Application**:
   - Use ` python app.py' to start the application.

4. **Testing**:
   - Use tools like Postman to test the API endpoints.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact

For any inquiries or support, please contact:
- **Name**: Shubham 
- **Email**: birarishubham3@gmail.com
- **GitHub**: [shubhambirari3](https://github.com/shubhambirari3)
