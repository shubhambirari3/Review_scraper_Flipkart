from flask import Flask, render_template, request, redirect, url_for, session
from flask_jwt_extended import JWTManager
from bs4 import BeautifulSoup
import requests
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import re
import os
from dotenv import load_dotenv
from urllib.parse import urlparse, urljoin
import time

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
jwt = JWTManager(app)

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept-Language': 'en-US,en;q=0.9',
}

# Database initialization
def init_db():
    conn = sqlite3.connect('scraped_data.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS reviews 
                 (id INTEGER PRIMARY KEY, user_id INTEGER, product TEXT, site TEXT, name TEXT, rating INTEGER, 
                  comment_head TEXT, comment TEXT, reviewed_on TEXT, scraped_at TIMESTAMP,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()

init_db()

# User class for authentication
class User:
    def __init__(self, id, username):
        self.id = id
        self.username = username
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False

    def get_id(self):
        return str(self.id)

@app.before_request
def load_user():
    if 'user_id' in session:
        conn = sqlite3.connect('scraped_data.db')
        c = conn.cursor()
        c.execute('SELECT id, username FROM users WHERE id = ?', (session['user_id'],))
        user_data = c.fetchone()
        conn.close()
        if user_data:
            request.current_user = User(user_data[0], user_data[1])
        else:
            request.current_user = None
    else:
        request.current_user = None

# Scrape reviews function for Flipkart
def scrape_reviews(all_reviews_url, num_reviews, product_name, site):
    reviews = []
    page_url = all_reviews_url
    base_url = 'https://www.flipkart.com'

    while len(reviews) < num_reviews and page_url:
        try:
            response = requests.get(page_url, headers=HEADERS)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Error fetching reviews page: {str(e)}")

        soup = BeautifulSoup(response.text, 'html.parser')
        review_containers = soup.find_all('div', class_='EPCmJX')

        if not review_containers:
            break  # No more reviews, exit the loop

        for container in review_containers:
            if len(reviews) >= num_reviews:
                break
            review = {}
            review['Product'] = product_name
            review['Site'] = site
            review['Name'] = container.find('p', class_='AwS1CA').text if container.find('p', class_='AwS1CA') else 'Anonymous'
            rating_text = container.find('div', class_='XQDdHH').text if container.find('div', class_='XQDdHH') else 'N/A'
            review['Rating'] = int(rating_text[0]) if rating_text != 'N/A' and rating_text[0].isdigit() else 0
            review['CommentHead'] = container.find('p', class_='z9E0IG').text if container.find('p', class_='z9E0IG') else 'No Heading'
            review['Comment'] = container.find('div', class_='ZmyHeo').text if container.find('div', class_='ZmyHeo') else 'No Comment'
            date_elements = container.find_all('p', class_='_2NsDsF')
            review['Reviewed On'] = date_elements[-1].text if date_elements else 'Unknown Date'
            reviews.append(review)
        
        next_button = soup.find('a', class_='_9QVEpD', string=lambda t: 'Next' in t if t else False)
        next_href = next_button['href'] if next_button and next_button.get('href') else None
        page_url = urljoin(base_url, next_href) if next_href else None
        time.sleep(1)  # Delay to avoid rate limits

    return reviews

# Scrape reviews function for Amazon from product detail page
def scrape_amazon_reviews(product_url, site):
    try:
        response = requests.get(product_url, headers=HEADERS)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise Exception(f"Error fetching product page: {str(e)}")

    soup = BeautifulSoup(response.text, 'html.parser')
    review_section = soup.find('div', class_='card-padding')
    if not review_section:
        return []

    # Find all review items within the card-padding section
    review_containers = review_section.find_all('li', attrs={'data-hook': 'review'})
    reviews = []

    for container in review_containers:
        review = {}
        review['Product'] = soup.title.text.split(":")[-1].strip()[:50]
        review['Site'] = site
        name_tag = container.find('span', class_='a-profile-name')
        review['Name'] = name_tag.text.strip() if name_tag else 'Anonymous'
        rating_tag = container.find('i', attrs={'data-hook': 'review-star-rating'})
        rating_text = rating_tag.find('span', class_='a-icon-alt').text if rating_tag else 'N/A'
        review['Rating'] = int(float(rating_text.split()[0])) if rating_text != 'N/A' and rating_text[0].isdigit() else 0
        heading_tag = container.find('a', attrs={'data-hook': 'review-title'})
        review['CommentHead'] = heading_tag.find('span').text.strip() if heading_tag and heading_tag.find('span') else 'No Heading'
        comment_tag = container.find('span', attrs={'data-hook': 'review-body'})
        review['Comment'] = comment_tag.text.strip() if comment_tag else 'No Comment'
        date_tag = container.find('span', attrs={'data-hook': 'review-date'})
        review['Reviewed On'] = date_tag.text.strip() if date_tag else 'Unknown Date'
        reviews.append(review)

    return reviews

# Helper function to parse "Reviewed On" dates
def parse_reviewed_on(date_str):
    if 'ago' in date_str.lower():
        match = re.search(r'(\d+)\s*(month|day)s?\s*ago', date_str.lower())
        if match:
            num, unit = int(match.group(1)), match.group(2)
            days = num * 30 if unit == 'month' else num
            return datetime.now() - timedelta(days=days)
    else:
        try:
            date_part = date_str.split(' on ')[-1]
            return datetime.strptime(date_part, '%d %B %Y')
        except:
            pass
    return datetime.now()

# Routes
@app.route('/')
def index():
    return render_template('index.html', current_user=request.current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('scraped_data.db')
        c = conn.cursor()
        c.execute('SELECT id, username, password FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            return redirect(url_for('index'))
        return render_template('login.html', error='Invalid credentials', current_user=request.current_user)
    return render_template('login.html', current_user=request.current_user)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password2 = request.form['password2']
        if password != password2:
            return render_template('signup.html', error='Passwords do not match', current_user=request.current_user)
        hashed_password = generate_password_hash(password)
        conn = sqlite3.connect('scraped_data.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            c.execute('SELECT id FROM users WHERE username = ?', (username,))
            user_id = c.fetchone()[0]
            session['user_id'] = user_id
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            return render_template('signup.html', error='Username already exists', current_user=request.current_user)
        finally:
            conn.close()
    return render_template('signup.html', current_user=request.current_user)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/review', methods=['POST'])
def review():
    if not request.current_user:
        return redirect(url_for('login'))
    product_url = request.form['product_url']
    num_reviews = min(int(request.form['num_reviews']), 100)

    parsed = urlparse(product_url)
    domain = parsed.netloc.lower()
    if 'flipkart.com' in domain:
        site = 'flipkart'
    elif 'amazon.in' in domain:
        site = 'amazon'
    else:
        return render_template('index.html', error="Unsupported URL. Please provide a Flipkart or Amazon product URL.", current_user=request.current_user)

    if site == 'flipkart':
        if not product_url.startswith('https://www.flipkart.com/') or '/p/' not in product_url:
            return render_template('index.html', error="Invalid Flipkart product URL. Please provide a valid product page URL.", current_user=request.current_user)
        path_parts = parsed.path.split('/')
        if len(path_parts) < 3 or path_parts[2] != 'p':
            return render_template('index.html', error="Invalid Flipkart product URL. URL must contain '/p/' indicating a product page.", current_user=request.current_user)
        slug = path_parts[1]
        product_name_full = slug.replace('-', ' ')
        product_name = ' '.join(product_name_full.split()[:10])
        reviews_url = product_url.replace('/p/', '/product-reviews/')
        try:
            reviews = scrape_reviews(reviews_url, num_reviews, product_name, site)
        except Exception as e:
            return render_template('index.html', error=str(e), current_user=request.current_user)
    elif site == 'amazon':
        try:
            reviews = scrape_amazon_reviews(product_url, site)
        except Exception as e:
            return render_template('index.html', error=str(e), current_user=request.current_user)

    if not reviews:
        message = "Amazon restricts access to all reviews. Search for this product on Flipkart to see more reviews." if site == 'amazon' else "No reviews found for this product."
        return render_template('results.html', reviews=[], product="", site=site, avg_rating=0, sort_by="", current_user=request.current_user, message=message)

    conn = sqlite3.connect('scraped_data.db')
    c = conn.cursor()
    for review in reviews:
        c.execute('''INSERT INTO reviews (user_id, product, site, name, rating, comment_head, comment, reviewed_on, scraped_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                  (request.current_user.id, review['Product'], review['Site'], review['Name'], review['Rating'], 
                   review['CommentHead'], review['Comment'], review['Reviewed On'], datetime.now()))
    conn.commit()
    conn.close()

    return redirect(url_for('results', product=reviews[0]['Product'], site=site))

@app.route('/results/<product>/<site>', methods=['GET'])
def results(product, site):
    if not request.current_user:
        return redirect(url_for('login'))
    conn = sqlite3.connect('scraped_data.db')
    c = conn.cursor()
    c.execute('SELECT product, site, name, rating, comment_head, comment, reviewed_on FROM reviews WHERE user_id = ? AND product = ? AND site = ?', 
              (request.current_user.id, product, site))
    reviews = [dict(zip(['Product', 'Site', 'Name', 'Rating', 'CommentHead', 'Comment', 'Reviewed On'], row)) for row in c.fetchall()]
    conn.close()
    
    if not reviews:
        return "No reviews found for this product", 404
    
    sort_by = request.args.get('sort_by', '')
    if sort_by == 'rating_asc':
        reviews.sort(key=lambda x: x['Rating'])
    elif sort_by == 'rating_desc':
        reviews.sort(key=lambda x: x['Rating'], reverse=True)
    elif sort_by == 'date_asc':
        reviews.sort(key=lambda x: parse_reviewed_on(x['Reviewed On']))
    elif sort_by == 'date_desc':
        reviews.sort(key=lambda x: parse_reviewed_on(x['Reviewed On']), reverse=True)

    avg_rating = sum(r['Rating'] for r in reviews) / len(reviews) if reviews else 0
    message = "Amazon restricts access to all reviews. Search for this product on Flipkart to see more reviews." if site == 'amazon' else ""
    return render_template('results.html', reviews=reviews, product=product, site=site, avg_rating=avg_rating, 
                           sort_by=sort_by, current_user=request.current_user, message=message)

if __name__ == '__main__':
    app.run(debug=True)