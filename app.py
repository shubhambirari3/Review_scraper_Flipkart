from flask import Flask, render_template, request, redirect, url_for, session, Response
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
from io import StringIO
import csv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept-Language': 'en-US,en;q=0.9',
}

# Database initialization
def init_db():
    with sqlite3.connect('scraped_data.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users 
                     (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS reviews 
                     (id INTEGER PRIMARY KEY, user_id INTEGER, product TEXT, site TEXT, name TEXT, rating INTEGER, 
                      comment_head TEXT, comment TEXT, reviewed_on TEXT, scraped_at TIMESTAMP,
                      FOREIGN KEY(user_id) REFERENCES users(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS contacts 
                     (id INTEGER PRIMARY KEY, name TEXT, email TEXT, message TEXT, submitted_at TIMESTAMP)''')
        conn.commit()

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
        with sqlite3.connect('scraped_data.db') as conn:
            c = conn.cursor()
            c.execute('SELECT id, username FROM users WHERE id = ?', (session['user_id'],))
            user_data = c.fetchone()
        if user_data:
            request.current_user = User(user_data[0], user_data[1])
        else:
            request.current_user = None
    else:
        request.current_user = None

# Scrape reviews function for Flipkart
def scrape_reviews(all_reviews_url, num_reviews, product_name):
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
            review['Site'] = 'flipkart'
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
        with sqlite3.connect('scraped_data.db') as conn:
            c = conn.cursor()
            c.execute('SELECT id, username, password FROM users WHERE username = ?', (username,))
            user = c.fetchone()
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
        with sqlite3.connect('scraped_data.db') as conn:
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
    try:
        num_reviews = min(int(request.form['num_reviews']), 100)
        if num_reviews <= 0:
            raise ValueError("Number of reviews must be positive.")
    except ValueError:
        return render_template('index.html', error="Number of reviews must be a valid positive integer.", current_user=request.current_user)

    if not product_url.startswith('https://www.flipkart.com/') or '/p/' not in product_url:
        return render_template('index.html', error="Invalid Flipkart product URL. Please provide a valid product page URL.", current_user=request.current_user)

    parsed = urlparse(product_url)
    path_parts = parsed.path.split('/')
    if len(path_parts) < 3 or path_parts[2] != 'p':
        return render_template('index.html', error="Invalid Flipkart product URL. URL must contain '/p/' indicating a product page.", current_user=request.current_user)
    slug = path_parts[1]
    product_name_full = slug.replace('-', ' ')
    product_name = ' '.join(product_name_full.split()[:10])
    reviews_url = product_url.replace('/p/', '/product-reviews/')

    try:
        reviews = scrape_reviews(reviews_url, num_reviews, product_name)
    except Exception as e:
        return render_template('index.html', error=str(e), current_user=request.current_user)

    if not reviews:
        return render_template('results.html', reviews=[], product=product_name, site='flipkart', avg_rating=0, sort_by="", current_user=request.current_user, message="No reviews found for this product.")

    with sqlite3.connect('scraped_data.db') as conn:
        c = conn.cursor()
        for review in reviews:
            c.execute('''INSERT INTO reviews (user_id, product, site, name, rating, comment_head, comment, reviewed_on, scraped_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                      (request.current_user.id, review['Product'], review['Site'], review['Name'], review['Rating'], 
                       review['CommentHead'], review['Comment'], review['Reviewed On'], datetime.now()))
        conn.commit()

    return redirect(url_for('results', product=reviews[0]['Product']))

@app.route('/results/<product>', methods=['GET'])
def results(product):
    if not request.current_user:
        return redirect(url_for('login'))
    with sqlite3.connect('scraped_data.db') as conn:
        c = conn.cursor()
        c.execute('SELECT product, site, name, rating, comment_head, comment, reviewed_on FROM reviews WHERE user_id = ? AND product = ?', 
                  (request.current_user.id, product))
        reviews = [dict(zip(['Product', 'Site', 'Name', 'Rating', 'CommentHead', 'Comment', 'Reviewed On'], row)) for row in c.fetchall()]
    
    if not reviews:
        return render_template('results.html', reviews=[], product=product, site='flipkart', avg_rating=0, sort_by="", current_user=request.current_user, message="No reviews found for this product.")
    
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
    return render_template('results.html', reviews=reviews, product=product, site='flipkart', avg_rating=avg_rating, 
                           sort_by=sort_by, current_user=request.current_user)

@app.route('/history')
def history():
    if not request.current_user:
        return redirect(url_for('login'))
    with sqlite3.connect('scraped_data.db') as conn:
        c = conn.cursor()
        c.execute('SELECT DISTINCT product, site FROM reviews WHERE user_id = ? ORDER BY scraped_at DESC', 
                  (request.current_user.id,))
        products = [dict(zip(['product', 'site'], row)) for row in c.fetchall()]
        avg_ratings = {}
        for p in products:
            c.execute('SELECT AVG(rating) FROM reviews WHERE user_id = ? AND product = ?', 
                      (request.current_user.id, p['product']))
            avg_rating = c.fetchone()[0]
            avg_ratings[(p['product'], p['site'])] = avg_rating if avg_rating else 0.0
    return render_template('history.html', products=products, avg_ratings=avg_ratings, current_user=request.current_user)

@app.route('/download_csv/<product>')
def download_csv(product):
    if not request.current_user:
        return redirect(url_for('login'))
    with sqlite3.connect('scraped_data.db') as conn:
        c = conn.cursor()
        c.execute('SELECT product, site, name, rating, comment_head, comment, reviewed_on FROM reviews WHERE user_id = ? AND product = ?', 
                  (request.current_user.id, product))
        reviews = [dict(zip(['Product', 'Site', 'Name', 'Rating', 'CommentHead', 'Comment', 'Reviewed On'], row)) for row in c.fetchall()]
    
    if not reviews:
        return render_template('results.html', reviews=[], product=product, site='flipkart', avg_rating=0, sort_by="", current_user=request.current_user, message="No reviews found for this product.")
    
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Product', 'Site', 'Customer Name', 'Rating', 'Heading', 'Comment', 'Reviewed On'])
    for review in reviews:
        cw.writerow([review['Product'], review['Site'], review['Name'], review['Rating'], review['CommentHead'], review['Comment'], review['Reviewed On']])
    
    output = si.getvalue()
    si.close()
    
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={product}_reviews.csv"}
    )

@app.route('/about')
def about():
    return render_template('about.html', current_user=request.current_user)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        # Basic validation
        if not name or not email or not message:
            return render_template('contact.html', error="All fields are required.", current_user=request.current_user)
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return render_template('contact.html', error="Invalid email address.", current_user=request.current_user)
        if len(name) > 100 or len(message) > 1000:
            return render_template('contact.html', error="Name or message too long.", current_user=request.current_user)

        try:
            with sqlite3.connect('scraped_data.db') as conn:
                c = conn.cursor()
                c.execute('''INSERT INTO contacts (name, email, message, submitted_at)
                             VALUES (?, ?, ?, ?)''', 
                          (name, email, message, datetime.now()))
                conn.commit()
            return render_template('contact.html', success="Your message has been sent successfully!", current_user=request.current_user)
        except Exception as e:
            return render_template('contact.html', error=f"An error occurred: {str(e)}", current_user=request.current_user)

    return render_template('contact.html', current_user=request.current_user)

if __name__ == '__main__':
    app.run(debug=True)