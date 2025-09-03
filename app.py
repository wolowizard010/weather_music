import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func
from datetime import datetime, timezone
import random

load_dotenv
app = Flask(__name__)

# --- Database Configuration ---

# using an absolute path for the database file
project_dir = os.path.dirname(os.path.abspath(__file__))
database_file = f"sqlite:///{os.path.join(project_dir, 'weather_music.db')}"
app.config["SECRET_KEY"] = "secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = database_file
db = SQLAlchemy(app)

with app.app_context():
    db.create_all()
    
# --- Database Models ---

# Users table
class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, unique=True, nullable=True)
    password_hash = db.Column(db.Text, nullable=False)
    is_guest = db.Column(db.Boolean, default=False)
    sessions = db.relationship('Session', backref='user', lazy=True)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    favorites = db.relationship('Favorite', backref='user', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Sessions table
class Session(db.Model):
    __tablename__ = 'sessions'
    session_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    end_time = db.Column(db.DateTime, nullable=True)
    weather_logs = db.relationship('WeatherLog', backref='session', lazy=True)
    recommendations = db.relationship('Recommendation', backref='session', lazy=True)

# Weather logs table
class WeatherLog(db.Model):
    __tablename__ = 'weather_logs'
    log_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    session_id = db.Column(db.Integer, db.ForeignKey('sessions.session_id'), nullable=False)
    location = db.Column(db.Text, nullable=False)
    temperature = db.Column(db.Float, nullable=False)
    condition = db.Column(db.Text, nullable=False)
    mood = db.Column(db.Text, nullable=False)

# Recommendations table
class Recommendation(db.Model):
    __tablename__ = 'recommendations'
    rec_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    session_id = db.Column(db.Integer, db.ForeignKey('sessions.session_id'), nullable=False)
    
    # Store spotify tracks info directly
    spotify_track_id = db.Column(db.String(100), nullable=False)
    title = db.Column(db.Text, nullable=False)
    artist = db.Column(db.Text, nullable=False)
    url = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=func.now(), default=lambda: datetime.now(timezone.utc))

# Favorite songs table
class Favorite(db.Model):
    __tablename__ = 'favorites'
    favorite_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    spotify_track_id = db.Column(db.String(100), nullable=False)
    title = db.Column(db.Text, nullable=False)
    artist = db.Column(db.Text, nullable=False)
    url = db.Column(db.Text, nullable=False)
    # to prevent a user from favoriting the same song twice
    __table_args__ = (db.UniqueConstraint('user_id', 'spotify_track_id', name='_user_track_uc'),)

# import all the functions from helpers.py
from helpers import *

# --- User Authentication and App Routes ---

@app.route('/')
def index():
    # If a user is logged in (and not a guest), show the main menu
    if 'user_id' in session and not session.get('is_guest'):
        return render_template('home.html')
    # Otherwise, show the landing page with login/register options
    return render_template('landing.html')

@app.route('/recommendations_page')
def recommendations_page():
    return render_template('recommendations.html')

@app.route('/get_recommendations')
def get_recommendations():
    try:
        lat = request.args.get('lat')                                                       # retrieve ip coordinates from the browser
        lon = request.args.get('lon')
        
        weather_data = get_weather_data(lat, lon)                                           # helper function

        if weather_data is None:
            return jsonify({"error": "Weather API returned an error."}), 500

        city = weather_data["city"]
        condition = weather_data["condition"]
        temp = weather_data["temp"]
        mood = map_weather_to_mood(condition)
        
        spotify_token = get_spotify_token()                                                 # helper function
        if not spotify_token:
            return jsonify({"error": "Failed to authenticate with Spotify."}), 500
        
        # fetch a list of song ids and cache them
        song_ids = fetch_playlist_tracks(spotify_token, mood, 0)                            # helper function
        session['song_id_cache'] = song_ids
        session['playlist_offset'] = 1

        # random sample of 12 ids from the cache
        sample_size = min(12, len(session['song_id_cache']))
        ids_to_serve = random.sample(session['song_id_cache'], sample_size)
        
        # remove the served ids from the cache
        session['song_id_cache'] = [song_id for song_id in session['song_id_cache'] if song_id not in ids_to_serve]
        
        # full details of the 12 songs being served
        songs_to_serve_details = get_track_details(spotify_token, ids_to_serve)             # helper function

        # Logging
        db_session_id = session.get('db_session_id')
        if db_session_id:
            # Log the weather and mood to the WeatherLog table
            weather_log = WeatherLog(
                session_id=db_session_id,
                location=city,
                temperature=temp,
                condition=condition,
                mood=mood
            )
            db.session.add(weather_log)
            db.session.commit()
        
        # return the values to the browser javascript
        return jsonify({
            "weather": {"city": city, "condition": condition, "temp": temp},
            "mood": mood,
            "songs": songs_to_serve_details
        })

    except Exception as e:
        print(f"--- AN ERROR OCCURRED ---: The error is '{e}'.")
        return jsonify({"error": "An internal server error occurred."}), 500

@app.route('/refresh_songs')
def refresh_songs():
    mood = request.args.get('mood')
    songs_to_serve_details = []
    
    spotify_token = get_spotify_token()
    if not spotify_token:
        return jsonify({"error": "Failed to authenticate."}), 500

    # If the ID cache has enough songs, serve from it
    if session.get('song_id_cache') and len(session['song_id_cache']) >= 12:
        print("Serving from ID cache...")
        ids_to_serve = random.sample(session['song_id_cache'], 12)
        session['song_id_cache'] = [song_id for song_id in session['song_id_cache'] if song_id not in ids_to_serve]
        songs_to_serve_details = get_track_details(spotify_token, ids_to_serve)             # helper function
    
    # Otherwise, fetch a new playlist of IDs
    else:
        print("ID cache is low. Fetching new playlist...")
        offset = session.get('playlist_offset', 1)
        new_song_ids = fetch_playlist_tracks(spotify_token, mood, offset)                   # helper function
        session['song_id_cache'] = new_song_ids
        session['playlist_offset'] = offset + 1

        sample_size = min(12, len(session['song_id_cache']))
        if sample_size > 0:
            ids_to_serve = random.sample(session['song_id_cache'], sample_size)
            session['song_id_cache'] = [song_id for song_id in session['song_id_cache'] if song_id not in ids_to_serve]
            songs_to_serve_details = get_track_details(spotify_token, ids_to_serve)         # helper function

    return jsonify({"songs": songs_to_serve_details})
    
@app.route('/log_click', methods=['POST'])
def log_click():
    # Logs a song click in the recommendations table.
    data = request.get_json()
    db_session_id = session.get('db_session_id')

    if data and db_session_id:
        recommendation_log = Recommendation(
            session_id=db_session_id,
            spotify_track_id=data.get('song_id'),
            title=data.get('title'),
            artist=data.get('artist'),
            url=data.get('url')
        )
        db.session.add(recommendation_log)
        db.session.commit()
        return jsonify({"status": "success"}), 200
    
    return jsonify({"status": "error", "message": "Missing data"}), 400

@app.route('/favorites')
@login_required
def favorites_page():
    user_id = session['user_id']
    # query the favorite songs table of the logged in user
    favorites = Favorite.query.filter_by(user_id=user_id).order_by(Favorite.title).all()
    return render_template('favorites.html', favorites=favorites)

@app.route('/recents')
@login_required
def recents_page():
    user_id = session['user_id']
    favorite_ids = {fav.spotify_track_id for fav in Favorite.query.filter_by(user_id=user_id).all()}

    # subquery to get the latest timestamp for each unique song for the user
    subq = db.session.query(
        Recommendation.spotify_track_id,
        func.max(Recommendation.timestamp).label('max_ts')
    ).join(Session).filter(Session.user_id == user_id).group_by(Recommendation.spotify_track_id).subquery()

    # join back to get the full song details for those latest timestamps (30 most recent)
    recents = db.session.query(Recommendation).join(
        subq,
        db.and_(Recommendation.spotify_track_id == subq.c.spotify_track_id, Recommendation.timestamp == subq.c.max_ts)
    ).order_by(Recommendation.timestamp.desc()).limit(30).all()
    
    return render_template('recents.html', recents=recents, favorite_ids=favorite_ids)

@app.route('/dashboard')
@login_required
@admin_required
def dashboard():
    popular_moods = db.session.query(
        WeatherLog.mood, func.count(WeatherLog.mood).label('count')
    ).group_by(WeatherLog.mood).order_by(func.count(WeatherLog.mood).desc()).limit(3).all()                     # top 3 moods
    popular_songs = db.session.query(
        Recommendation.title, func.count(Recommendation.title).label('count')
    ).group_by(Recommendation.title).order_by(func.count(Recommendation.title).desc()).limit(10).all()          # top 10 songs

    # logged-in vs. guest session counts
    session_types_query = db.session.query(User.is_guest, func.count(Session.session_id)).join(User).group_by(User.is_guest).all()
    session_types = {'guest': 0, 'registered': 0}
    for is_guest, count in session_types_query:
        if is_guest:
            session_types['guest'] = count
        else:
            session_types['registered'] = count

    # number of sessions per day
    sessions_per_day = db.session.query(
        func.date(Session.start_time), 
        func.count(Session.session_id)
    ).group_by(func.date(Session.start_time)).order_by(func.date(Session.start_time).desc()).limit(10).all()

    # peak usage hour for each day
    hourly_counts = db.session.query(
        func.date(Session.start_time).label('day'),
        func.strftime('%H', Session.start_time).label('hour'),
        func.count(Session.session_id).label('count')
    ).group_by('day', 'hour').all()
    
    peak_hours_by_day = {}
    for day, hour, count in hourly_counts:
        # if this is the 1st log of the day or if the current hours count is higher
        if day not in peak_hours_by_day or count > peak_hours_by_day[day]['count']:
            peak_hours_by_day[day] = {'hour': int(hour), 'count': count}

    # pass all the data to the template
    return render_template(
        'dashboard.html', 
        popular_moods=popular_moods, 
        popular_songs=popular_songs,
        session_types=session_types,
        sessions_per_day=sessions_per_day,
        peak_hours_by_day=peak_hours_by_day
    )

@app.route('/toggle_favorite', methods=['POST'])
@login_required
def toggle_favorite():
    data = request.get_json()
    user_id = session['user_id']
    track_id = data.get('song_id')
    
    existing_fav = Favorite.query.filter_by(user_id=user_id, spotify_track_id=track_id).first()
    
    if existing_fav:
        db.session.delete(existing_fav)
        db.session.commit()
        return jsonify({'favorited': False})
    else:
        new_fav = Favorite(
            user_id=user_id,
            spotify_track_id=track_id,
            title=data.get('title'),
            artist=data.get('artist'),
            url=data.get('url')
        )
        db.session.add(new_fav)
        db.session.commit()
        return jsonify({'favorited': True})

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        # check if user already exists
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists.', 'error')
            return redirect(url_for('register'))

        # add user in the database
        new_user = User(name=name, email=email, is_guest=False)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('You have successfully registered! Please login.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()

        if not user or not user.check_password(password):
            flash('Please check your login details and try again.', 'error')
            return redirect(url_for('login'))
        
        # create session in flask
        session['user_id'] = user.user_id
        session['name'] = user.name
        session['is_guest'] = False
        session['is_admin'] = user.is_admin
        
        # log the session in the database
        new_session = Session(user_id=user.user_id)
        db.session.add(new_session)
        db.session.commit()
        
        # store the new session_id in the flask session for later use
        session['db_session_id'] = new_session.session_id
        
        return redirect(url_for('index'))

    return render_template('login.html')

@app.route('/guest')
def guest_login():
    # create a new guest user account
    guest_name = f"Guest_{User.query.filter_by(is_guest=True).count() + 1}"
    guest_user = User(name=guest_name, is_guest=True)
    guest_user.set_password('dummy_password') # set a dummy password
    db.session.add(guest_user)
    db.session.commit()
    
    # create session in flask
    session['user_id'] = guest_user.user_id
    session['is_guest'] = True

    # log the guest session in the database
    new_session = Session(user_id=guest_user.user_id)
    db.session.add(new_session)
    db.session.commit()

    # store the new session_id in the flask session for later use
    session['db_session_id'] = new_session.session_id

    return redirect(url_for('recommendations_page'))


@app.route('/logout')
def logout():
   # get the unique database session ID from the browser's session cookie
    db_session_id = session.get('db_session_id')

    # find the session in the database and update its end_time
    if db_session_id:
        # query the database for the session with this ID
        current_db_session = db.session.get(Session, db_session_id)
        if current_db_session:
            current_db_session.end_time = datetime.now(timezone.utc)
            db.session.commit()
            
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


# --- Development Server ---
if __name__ == "__main__":
    app.run(debug=True)