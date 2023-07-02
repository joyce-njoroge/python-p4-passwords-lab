#!/usr/bin/env python3

from flask import request, session, jsonify, session
from flask_restful import Resource
from werkzeug.security import generate_password_hash

from config import app, db, api
from models import User

class ClearSession(Resource):

    def delete(self):
    
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204

class Signup(Resource):
    
    def post(self):
        
        username = request.json['username']
        password = request.json['password']

        user = User(username=username)
        user.password_hash = password
        db.session.add(user)
        db.session.commit()

        # Return the serialized user object as JSON
        return user.serialize(), 201

        

class CheckSession(Resource):
    def get(self):
        if 'user_id' in session:
            user_id = session['user_id']
            user = User.query.get(user_id)

            if user:
                return jsonify({'username': user.username}), 200

        return jsonify({'message': 'User not authenticated.'}), 401
    
class Login(Resource):
    users = [
        {
            'username': 'ash',
            'password': 'pikachu',
            'id': 1
        }
    ]

    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password']

        # Find the user with matching credentials
        user = next((user for user in self.users if user['username'] == username and user['password'] == password), None)

        if user:
            # Store user ID in session
            session['user_id'] = user['id']
            # Return the user as JSON
            return jsonify(user)
        else:
            return jsonify({'message': 'Invalid credentials'}), 401
        
    def delete(self):
        # Clear the user ID from the session
        session.pop('user_id', None)
        return jsonify({'message': 'Logged out successfully'})


class Logout(Resource):
    def delete(self):
        session.pop('user_id', None)
        return jsonify({'message': 'Logout successful.'}), 200
    
api.add_resource(Login, '/login')
api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(Logout, '/logout')
api.add_resource(CheckSession, '/check_session')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
