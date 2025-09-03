import os
import requests
import base64
from functools import wraps
from flask import flash, redirect, url_for, session

# --- Helper functions ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('is_guest'):
            flash('You need to be logged in to view this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            return "<h1>Access Denied</h1>", 403
        return f(*args, **kwargs)
    return decorated_function

# Fetches weather details of ip coordinates from openweathermap API 
def get_weather_data(lat, lon):
    api_key = os.getenv("WEATHER_API_KEY")
    if not api_key: return None
    weather_url = f"http://api.openweathermap.org/data/2.5/weather?lat={lat}&lon={lon}&appid={api_key}&units=metric"
    try:
        weather_response = requests.get(weather_url)
        if weather_response.status_code != 200: return None
        weatherdata = weather_response.json()
        return {
            "city": weatherdata.get("name", "Unknown"),
            "condition": weatherdata["weather"][0]["main"],
            "temp": weatherdata["main"]["temp"]
        }
    except requests.RequestException:
        return None

# Simple weather-mood mapping
def map_weather_to_mood(weather_condition):
    mapping = {
        "Clear": "Happy",
        "Clouds": "Energetic",
        "Rain": "Sad",
        "Drizzle": "Sad",
        "Thunderstorm": "Energetic",
        "Snow": "Peaceful",
        "Mist": "Calm",
        "Smoke": "Calm",
        "Haze": "Peaceful",
        "Fog": "Sad",
    }
    # returns the mood from the mapping, or "Happy" as a default
    return mapping.get(weather_condition, "Happy")

# Gets an access token from the Spotify API.
def get_spotify_token():
    client_id = os.getenv("SPOTIFY_CLIENT_ID")
    client_secret = os.getenv("SPOTIFY_CLIENT_SECRET")
    auth_url = 'https://accounts.spotify.com/api/token'
    auth_header = base64.b64encode(f"{client_id}:{client_secret}".encode('utf-8')).decode('utf-8')
    
    auth_response = requests.post(auth_url, {
        'grant_type': 'client_credentials'
    }, headers={
        'Authorization': f'Basic {auth_header}'
    })
    
    auth_response_data = auth_response.json()
    token = auth_response_data.get('access_token')
    return token

# Searches for playlists matching the mood and fetches track ids from the top available playlist.
def fetch_playlist_tracks(token, mood, offset=0):
    # Playlist search
    search_url = 'https://api.spotify.com/v1/search'
    query = f"{mood.lower()} english songs"
    params = {
        'q': query,
        'type': 'playlist',
        'limit': 1,
        'offset': offset,
        'market': 'US'
    }
    headers = {"Authorization": f"Bearer {token}"}
    search_response = requests.get(search_url, headers=headers, params=params)

    if search_response.status_code != 200:
        return []
    
    search_data = search_response.json()
    playlists = search_data.get("playlists", {}).get("items", [])

    if not playlists:
        print(f"No playlists found for query: {query}")
        return []

    # Get the tracks from the first playlist found
    playlist_id = playlists[0]["id"]
    playlist_tracks_url = f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks"
    tracks_response = requests.get(playlist_tracks_url, headers=headers)

    if tracks_response.status_code != 200:
        return []
    
    tracks_data = tracks_response.json()
    
    # Return the track_ids of the tracks
    track_ids = []
    for item in tracks_data.get("items", []):
        track = item.get("track")
        if track:
            track_ids.append(track["id"])
    
    return track_ids

# Full track details for a list of Spotify track IDs.
def get_track_details(token, track_ids):
    if not track_ids:
        return []
        
    ids_string = ",".join(track_ids)
    tracks_url = f"https://api.spotify.com/v1/tracks?ids={ids_string}"
    
    headers = {"Authorization": f"Bearer {token}"}
    tracks_response = requests.get(tracks_url, headers=headers)
    
    if tracks_response.status_code != 200:
        print('Unable to get tracks details.')
        return []
        
    tracks_data = tracks_response.json()
    song_list = []
    for track in tracks_data.get("tracks", []):
        if track:
            song_list.append({
                "id": track["id"],
                "title": track["name"],
                "artist": ", ".join([artist["name"] for artist in track["artists"]]),
                "url": track["external_urls"]["spotify"]
            })
    return song_list