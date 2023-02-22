
import hashlib
import jwt
import mysql.connector
from flask import abort

db_config = {
    'host': 'sre-bootcamp-selection-challenge.cabf3yhjqvmq.us-east-1.rds.amazonaws.com',
    'port': 3306,
    'user': 'secret',
    'password': 'jOdznoyH6swQB9sTGdLUeeSrtejWkcw',
    'database': 'bootcamp_tht'
}
jwt_secret = 'my2w7wjd7yXF64FIADfJxNs1oupTGAuW'

class Token:

    def generate_token(self, username, password):
        #Connecting to the database
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        #Obtaining the users from the database
        query = "SELECT password, salt, role FROM users WHERE username =%s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()

        #Close the database connection
        cursor.close()
        conn.close()

        #Return None if the user doesn't exist
        if result is None:
            abort(403, 'No user found.')
        
        #Assign the result to variables
        stored_password, salt, role = result

        #Hash the provided password with the stored salt using the SHA512 algorithm
        hashed_password = hashlib.sha512((password + salt).encode()).hexdigest()

        if hashed_password == stored_password:
            # If the password is valid, generate a JWT token with the role in the payload.
            payload = {'role': role}
            token = jwt.encode(payload, jwt_secret, algorithm='HS512')
            return token
        else:
            abort(403, 'Wrong password.')


class Restricted:

    def access_data(self, authorization):
        #Considering that the token is sent using Bearer + Token
        auth_token = authorization.split(' ')[1]
        try:
            payload = jwt.decode(auth_token, jwt_secret, algorithms=['HS512'])
            role = payload['role']
            
            # Only the 'admin' role can access the protected data.
            if role == 'admin':
                data = 'You are under protected data'
            else:
                data = "You don't have access to this data"
                
            return data
        except jwt.InvalidTokenError:
            # Token is invalid
            return "Invalid token received."
