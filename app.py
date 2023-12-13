from resource import app


if __name__ == '__main__':
    app.run(debug=True)














# from flask import Flask
# from flask_restful import Api, Resource
# from flasgger import Swagger
#
# app = Flask(__name__)
# api = Api(app)
# swagger = Swagger(app)
#
#
# class Hello(Resource):
#     def get(self):
#         """
#         This is a sample endpoint that returns a greeting message.
#         ---
#         responses:
#           200:
#             description: A simple greeting message.
#         """
#         return {"message": "Hello, Flask-RESTful!"}
#
#
# api.add_resource(Hello, '/hello')
#
#
# if __name__ == '__main__':
#     app.run(debug=True, port=3000)
