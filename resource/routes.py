from flask import request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt, create_refresh_token
from flask_restx import Resource, Namespace, fields
from resource import db, bcrypt
from resource.models import Users, RevokeToken, DishView
from datetime import datetime
import base64
from flask import make_response

user = Namespace("user", description="Operations on users..")
dish = Namespace("dish", description="Operations regarding dishes..")

user_model = user.model('Users', {
    'id': fields.Integer(required=True, description='User id'),
    'firstname': fields.String(required=True, description='User first name'),
    'lastname': fields.String(required=True, description='User last name'),
    'email': fields.String(required=True, description='User email'),
    'password': fields.String(required=True, description='User password'),
    'phone': fields.String(required=True, description='User phone'),
})

user_login = user.model("UserLogin", {
    "email": fields.String(required=True, description="user email"),
    "password": fields.String(required=True, description="user password")
})

dish_model = dish.model('Dish', {
    'id': fields.Integer(required=True, description='Dish id'),
    'name': fields.String(required=True, description='Dish name'),
    'Instructions': fields.String(required=True, description='Dish instruction'),
    'Ingredients': fields.List(fields.String(description="Ingredient", required=True)),
    'date_posted': fields.DateTime(description="Date when the dish was posted")
})

dish_view_model = dish.model("DishView", {
    'id': fields.Integer(required=True, description='DishView id'),
    'name': fields.String(required=True, description='DishView name'),
    'Instructions': fields.String(required=True, description='Instruction'),
    'Ingredients': fields.List(fields.String(), required=True, description="Ingredient"),
    'date_posted': fields.DateTime(required=True, description="Date when the dish was viewed"),
    "dish_image_url": fields.String(required=True, description="Dish image"),
    "user_id": fields.Integer(required=True, description="user id"),
    "user_likes": fields.List(fields.Nested(user_model), required=True)
})


# @api.route("/swagger")
# class Swagger(Resource):
#     def get(self):
#         pass


# >>>>>>>>>>> Endpoints for operations on user <<<<<<<<<<<<<<
@user.route('/register')
class Register(Resource):
    @user.doc(description="user registration")
    @user.expect(user_model, dish.parser().add_argument('X-Fields', location='headers', required=False),
                 validate=True)
    @user.response(200, "user created successfully")
    @user.response(400, "user with email address already exist")
    def post(self):
        data = request.get_json()
        firstname = data.get("firstname")
        lastname = data.get("lastname")
        email = data.get("email")
        password = data.get("password")
        phone = str(data.get("phone"))

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        email_exist = Users.query.filter_by(email=email).first()

        if email_exist:
            response = {
                "Error": "Email already exist..."
            }
            return jsonify(response)

        new_user = Users(firstname=firstname,
                         lastname=lastname,
                         email=email,
                         password=hashed_password,
                         phone=phone)

        db.session.add(new_user)
        db.session.commit()

        return {
            "message": "User created successfully...",
            "firstname": firstname,
            "lastname": lastname,
            "email": email,
            "phone": phone
        }, 200


def verify_user(email, password):
    """Function that verify each user login"""
    # Retrieve the user from the database based on the provided email
    user = Users.query.filter_by(email=email).first()

    if user and bcrypt.check_password_hash(user.password, password):
        return user.id

    return None


@user.route("/login")
class Login(Resource):
    @user.doc(description="Generate access token")
    @user.expect(user_login, validate=True)
    @user.response(200, "User successfully logged in", user_login)
    @user.response(400, "Invalid credentials")
    def post(self):
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        # user_login = Users.query.filter_by(email=email).first()

        user_id = verify_user(email, password)
        if user_id:
            # if user_login and bcrypt.check_password_hash(user_login.password, password):
            access_token = create_access_token(identity=user_id)
            refresh_token = create_refresh_token(identity=user_id)
            return {"access_token": access_token, "refresh_token": refresh_token}, 200

        return {"Message": "Invalid Credentials!"}, 401


@user.route("/welcome")
class Welcome(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        return {"user_id": current_user}, 200


"""needs a valid refresh token. You might have obtained a refresh token by initially logging in and receiving both an 
access token and a refresh token. Use the obtained refresh token in the request's authorization or body to test the 
/refresh endpoint."""


@user.route("/refresh")
class RefreshToken(Resource):
    @jwt_required(refresh=True)
    @user.doc(description="Refresh token", security="jwt")
    @user.response(200, "access token generated")
    @user.response(400, "user not logged in")
    def post(self):
        current_user = get_jwt_identity()
        refresh_token = create_refresh_token(identity=current_user)

        return {"refresh_token": refresh_token}, 200


# @app.route('/refresh', methods=['POST'])
# @jwt_required(refresh=True)
# def refresh():
#     current_user = get_jwt_identity()
#     new_access_token = create_access_token(identity=current_user, expires_delta=False)  # Generate a new access token
#     return jsonify(access_token=new_access_token), 200


@user.route("/logout")
class Logout(Resource):
    @jwt_required(refresh=True)
    @user.doc(description="Logout user", security="jwt")
    def post(self):
        jti = get_jwt()["jti"]
        revoke_token = RevokeToken(jti=jti)

        db.session.add(revoke_token)
        db.session.commit()

        return {"message": "User successfully logged out!!"}, 200


# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

"""Creating a dish"""


@dish.route("")
class PostDishView(Resource):
    @jwt_required(refresh=True)
    @dish.expect(dish_model, validate=True)
    @dish.response(201, "Dish created successfully")
    @dish.response(400, "Bad request")
    @dish.doc(description="Creating a dish", security="jwt")
    def post(self):
        data = request.get_json()

        name = data.get("name")
        instructions = data.get("Instructions")
        ingredients = data.get("Ingredients")
        date_posted = datetime.utcnow()
        dish_image_url = data.get("dish_image_url")
        user_ids = data.get("user_likes", [])

        if not all([name, instructions, ingredients, dish_image_url]):
            return {"Error": "Missing some fields"}, 400

        try:
            image64 = base64.b64decode(dish_image_url)
        except Exception as e:
            return {"Error": "Invalid image data"}, 400

        new_dish = DishView(
            name=name,
            Instructions=instructions,
            Ingredients=ingredients,
            date_posted=date_posted,
            dish_image_url=image64,
            user_id=2
        )

        if image64:
            new_dish.dish_image_url = image64

        # if not user_ids:
        #     return {"Error": f"User with ID {user_ids} not found!"}

        for user_id in user_ids:
            user = Users.query.get(user_id)
            if user:
                new_dish.user_likes.append(user)

                #     try:
                #         new_dish.user_likes.append(user)
                #     except sqlalchemy.exc.IntegrityError as e:
                #         return {"Error": f"Error associating user with ID {user_id} to the DishView"}, 400
                # else:
                return {"Error": f"User with ID {user_id} not found!"}, 404

        try:
            db.session.add(new_dish)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return {f"Failed to create Dishview: {str(e)}"}, 500

        return jsonify(
            {
                "message": f"Dish successfully created for {user_ids}",
                "dish_view_id": new_dish.id
            }
        )


# Get all the dishes in the DishView table
@dish.route("/")
class GetDishView(Resource):
    @jwt_required(refresh=True)
    @dish.expect(dish.parser().add_argument('X-Fields', location='headers', required=False),
                 validate=True)
    @dish.response(200, "Success", dish_view_model)
    @dish.response(400, "Not found")
    @dish.doc(description="Get all dishes")
    def get(self):
        dishes = DishView.query.all()
        users = Users.query.all()

        recipe_list = []
        for dish in dishes:
            user_likes = []
            for user in users:
                if user in dish.user_likes:
                    user_data = {
                        "id": user.id,
                        "first_name": user.firstname,
                        "last_name": user.lastname,
                        "email": user.email,
                        "password": user.password,
                        "phone_number": user.phone
                    }
                    user_likes.append(user_data)

            recipe_data = {
                "id": dish.id,
                "name": dish.name,
                "instructions": dish.Instructions,
                "ingredients": dish.Ingredients,
                "date_posted": dish.date_posted.isoformat(),
                "user_likes": user_likes,
                # "dish_image_url": dish.dish_image_url.encode() if dish.dish_image_url else "",
                "user_id": dish.user_id
            }
            recipe_list.append(recipe_data)

        response = {"recipes": recipe_list}
        return jsonify(response)


# uploading a dish image by dish_id
@dish.route("/image/<int:dish_id>/")
class UpdateDishImage(Resource):
    @jwt_required(refresh=True)
    @dish.response(201, "Imagae uploaded successfully")
    @dish.response(400, "Bad request")
    @dish.response(500, "Server error")
    @dish.doc(description="Uploading an image", security="jwt")
    def put(self, dish_id):
        data = request.get_json()
        dish = DishView.query.get(dish_id)

        if dish is None:
            return {"error": f"Dish with ID {dish_id} does not exist"}

        if "dish_image_data" in data:
            try:
                # Assuming 'dish_image_data' contains base64 encoded image data
                image_data = data["dish_image_data"]
                decoded_image = base64.b64decode(image_data)
                dish.dish_image_url = decoded_image
                db.session.commit()
                return {"message": f"Image updated for dish ID {dish_id}"}, 200
            except Exception as e:
                db.session.rollback()
                return {"error": str(e)}, 500
        else:
            return {"error": "No image data provided"}, 400


# Endpoint to view dish image by dish_id
@dish.route("/image/view/<int:dish_id>")
class ViewDishImage(Resource):
    @dish.response(201, "Image viewed successfully")
    @dish.response(404, "Not found")
    @dish.response(500, "Server error")
    def get(self, dish_id):
        dish = DishView.query.get(dish_id)

        if dish is None:
            return {"error": f"Dish with ID {dish_id} does not exist"}, 404

        dish_image = dish.dish_image_url

        if dish_image:
            encoded_image = base64.b64encode(dish_image).decode("utf-8")
            response = make_response(encoded_image)
            response.headers.set('Content-Type', 'image')  # Adjust the content type based on the image format
            return response

        return {"error": "No image found for this dish"}, 404


# Delete a dish image by dish_id
@dish.route("/image/delete/<int:dish_id>")
class DeleteDishImage(Resource):
    @dish.response(201, "Imagae deleted successfully")
    @dish.response(404, "Not found")
    @dish.response(500, "Server unavailable")
    @jwt_required(refresh=True)
    @dish.doc(description="Delete an image", security="jwt")
    def delete(self, dish_id):
        dish = DishView.query.get(dish_id)

        if dish is None:
            return {"error": f"Dish with ID {dish_id} does not exist"}, 404

        dish.dish_image_url = None
        # Assuming dish_image_url is a column holding image data
        # Delete the record from the database

        db.session.commit()

        return {"message": f"Image for dish ID {dish_id} deleted successfully"}, 200


# USER LIKES User likes dishes
@dish.route("/likes/<int:dish_id>")
class LikeDish(Resource):
    @jwt_required(refresh=True)
    @dish.doc(description="like a dish", security="jwt")
    @dish.response(201, "like successful")
    @dish.response(403, "Forbidden")
    @dish.response(404, "Not found")
    def post(self, dish_id):
        current_user_id = get_jwt_identity()

        user = Users.query.get(current_user_id)
        dish = DishView.query.get(dish_id)

        if not user or not dish:
            return {"Error": "User or dish not found!"}

        if user in user.liked_dishes:
            return {"Error": "User already liked the dish"}

        # if dish in user.liked_dishes.all():
        #     user.liked_dishes.remove(dish)
        #     db.session.commit()
        #     return {"message": "Dish disliked successfully"}

        user.liked_dishes.append(dish)
        db.session.commit()

        return {"message": "Dish liked successful"}
        # user.liked_dishes.append(dish)
        # db.session.commit()
        #
        # return {"message": "Dish liked successful"}


# Get all the dishes by a particular user
@dish.route("/user/<int:user_id>")
class GetDishByUser(Resource):
    @jwt_required(refresh=True)
    @dish.expect(dish.parser().add_argument('X-Fields', location='headers', required=False),
                 validate=True)
    @dish.response(200, "Success", dish_view_model)
    @dish.response(400, "Not found")
    @dish.doc(description="User", security="jwt")
    def get(self, user_id):
        user = Users.query.get(user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        user_dishes = DishView.query.filter_by(user_id=user_id).all()

        dish_list = []
        for dish in user_dishes:
            dish_data = {
                "id": dish.id,
                "name": dish.name,
                "instructions": dish.Instructions,
                "ingredients": dish.Ingredients,
                "date_posted": dish.date_posted.isoformat(),

            }
            dish_list.append(dish_data)

        response = {
            "user_id": user_id,
            "dishes": dish_list
        }
        return jsonify(response)


# updating a dish by dish_id
@dish.route("/<int:dish_id>")
class UpdateDish(Resource):
    @jwt_required(refresh=True)
    @dish.doc(description="Updating a dish", security="jwt")
    @dish.response(201, "dish updated successfully")
    @dish.response(403, "Forbidden")
    @dish.response(404, "Not found")
    def put(self, dish_id):
        data = request.get_json()
        dish = DishView.query.get(dish_id)

        if dish is None:
            return {"error": f"dish with dish_id {dish_id} does not exist! "}

        if "name" in data:
            dish.name = data["name"]
        if "instructions" in data:
            dish.instructions = data["Instructions"]
        if "ingredients" in data:
            dish.ingredients = data["Ingredients"]

        db.session.commit()

        return {"message": f"Dish updated for dish ID {dish_id} successfully!"}


# delete a dish by dish ID
@dish.route("/delete/<int:dish_id>")
class DeleteDish(Resource):
    @jwt_required(refresh=True)
    @dish.doc(description="Delete a dish", security="jwt")
    @dish.response(201, "Dish deleted successfully")
    @dish.response(403, "Forbidden")
    @dish.response(404, "Not found")
    def delete(self, dish_id):
        dish = DishView.query.get(dish_id)

        if dish:
            try:
                db.session.delete(dish)
                db.session.commit()
                return {"message": f"Dish with ID {dish_id} deleted successfully"}, 200
            except Exception as e:
                db.session.rollback()
                return {"error": str(e)}, 500
        else:
            return {"error": f"Dish with ID {dish_id} not found"}, 404


# get a single dish
@dish.route("/dishes/<int:dish_id>")
class GetSingleDish(Resource):
    @dish.response(201, "Success", dish_model)
    @dish.response(404, "Not found")
    @dish.doc(description="Get a particular dish")
    def get(self, dish_id):
        dish = DishView.query.get(dish_id)

        if dish:
            response = {
                "resource": {
                    "id": dish.id,
                    "name": dish.name,
                    "instructions": dish.Instructions,
                    "ingredients": dish.Ingredients,
                    "date_posted": dish.date_posted.isoformat()
                }
            }
            return response, 200
        else:
            return {"error": f"Dish with ID {dish_id} not found"}, 404

# # testing not working
# @dish.route("/create-dish")
# class GetDishVIew(Resource):
#     # @jwt_required()
#     def post(self):
#         data = request.get_json()
#         name = data.get("name")
#         instructions = data.get("Instructions")
#         ingredients = data.get("Ingredients")
#         dish_image_url = data.get("dish_image_url")
#         user_email = data.get("user_email")
#
#         if not all([name, instructions, ingredients, dish_image_url, user_email]):
#             return {"error": "Missing required fields"}, 400
#
#         try:
#             image_data = base64.b64decode(dish_image_url)
#         except Exception as e:
#             return {"error": "Invalid image data"}, 400
#
#         # Check if the user already exists
#         user = Users.query.filter_by(email=user_email).first()
#
#         if not user:
#             # Create a new user
#             user = Users(email=user_email)
#             db.session.add(user)
#             db.session.commit()
#
#         # Create a new dish associated with the user
#         new_dish = Dish(
#             name=name,
#             instructions=instructions,
#             ingredients=ingredients,
#             date_posted=datetime.utcnow(),
#             dish_image=image_data,
#             user_id=user.id  # Associate the dish with the user
#         )
#
#         try:
#             db.session.add(new_dish)
#             db.session.commit()
#
#             return {
#                 "message": "Dish created successfully",
#                 "dish_id": new_dish.id,
#                 "user_id": user.id
#             }, 201
#
#         except Exception as e:
#             db.session.rollback()
#             return {"error": f"Failed to create dish: {str(e)}"}, 500
#
#
# # Endpoint working to get all the dishes in the DishView table
# @dish.route("/get-dish-view")
# class GetDishVIew(Resource):
#     def get(self):
#         dishes_with_likes = DishView.query.all()
#
#         dishes_data = []
#         for dish in dishes_with_likes:
#             users_liked = [
#                 {
#                     "id": user.id,
#                     "firstname": user.firstname,
#                     "lastname": user.lastname,
#                     "email": user.email,
#                     "phone": user.phone
#                 } for user in dish.user_likes
#             ]
#
#             image64 = base64.b64encode(dish.dish_image_url).decode("utf-8")
#
#             dish_data = {
#                 "id": dish.id,
#                 "name": dish.name,
#                 "Instructions": dish.Instructions,
#                 "Ingredients": dish.Ingredients,
#                 "date_posted": dish.date_posted.isoformat(),
#                 "dish_image_url": image64,
#                 "user_id": dish.user_id,
#                 "users_liked": users_liked
#             }
#             dishes_data.append(dish_data)
#
#         return {"dishes_with_likes": dishes_data}, 200


# Not functioning endpoints
# @dish.route("/dish-user")
# class GetDishView(Resource):
#     def post(self):
#         data = request.get_json()
#
#         name = data.get("name")
#         instructions = data.get("Instructions")
#         ingredients = data.get("Ingredients")
#         dish_image_url = data.get("dish_image_url")
#         user_data = data.get("user_data", {})
#
#         if not all([name, instructions, ingredients, dish_image_url]):
#             return {"Error": "Missing some fields"}, 400
#
#         try:
#             image64 = base64.b64decode(dish_image_url)
#         except Exception as e:
#             return {"Error": "Invalid image data"}, 400
#
#         new_dish = DishView(
#             name=name,
#             Instructions=instructions,
#             Ingredients=ingredients,
#             dish_image_url=image64
#         )
#
#         if user_data:
#             new_user = Users(**user_data)
#             new_dish.user = new_user
#
#         db.session.add(new_dish)
#         db.session.commit()
#
#         return jsonify(
#             {
#                 "message": "Dish successfully created",
#                 "dish_view_id": new_dish.id,
#                 "user_id": new_user.id if user_data else None
#             }
#         )
#
#
# # Endpoint working but returning an empty list
# @dish.route("/")
# class CreateDish(Resource):
#     dish.expect(dish_model, validate=True)
#
#     # @jwt_required(refresh=True)
#     @dish.doc(description="create a new dish")
#     def post(self):
#         data = request.get_json()
#
#         name = data.get("name")
#         instructions = data.get("Instructions")
#         ingredients = data.get("Ingredients")
#         date_posted = datetime.utcnow()
#         dish_image = data.get("dish_image_url")
#         # user_id = data.get("user_id")
#
#         user_ids = data.get("user_likes", [])
#
#         users = Users.query.filter(Users.id.in_(user_ids)).all()
#
#         # if user is None:
#         #     return {"error": "User not found"}
#
#         dish_image64 = base64.b64decode(dish_image)
#
#         new_dish = DishView(
#             name=name,
#             Instructions=instructions,
#             Ingredients=ingredients,
#             date_posted=date_posted,
#             dish_image_url=dish_image64,
#             user_likes=[user.id for user in users]
#         )
#
#         if not isinstance(ingredients, list):
#             return {"error": "field must be a list"}
#
#         if dish_image64:
#             new_dish.dish_image_url = dish_image64
#
#         db.session.add(new_dish)
#         db.session.commit()
#
#         return {
#             "id": new_dish.id,
#             "name": new_dish.name,
#             "instructions": new_dish.Instructions,
#             "ingredients": new_dish.Ingredients,
#             "user_likes": [
#                 {
#                     "id": user.id,
#                     "firstname": user.firstname,
#                     "lastname": user.lastname,
#                     "email": user.email,
#                     "phone": user.phone
#                 } for user in users
#             ],
#             "date_posted": new_dish.date_posted.isoformat(),
#             "image": "Image added successfully",
#             "user_id": new_dish.user_id
#         }, 200
#
#
# # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# #
# #
# # @dish.route("/<int:dish_id>")
# # class GetDishView(Resource):
# #     def get(self, dish_id):
# #         dish_view = DishView.query.get(dish_id)
# #
# #         if not dish_view:
# #             return {"error": "dish not found"}
# #
# #         data = base64.b64encode(dish_view.dish_image_url).decode("utf-8")
# #
# #         serialized_dish = {
# #             "id": dish_view.id,
# #             "name": dish_view.name,
# #             "instructions": dish_view.Instructions,
# #             "ingredients": dish_view.Ingredients,
# #             "date_posted": dish_view.date_posted.isoformat(),
# #             "user_likes": [
# #                 {
# #                     "id": user.id,
# #                     "firstname": user.firstname,
# #                     "lastname": user.lastname,
# #                     "email": user.email,
# #                     "phone": user.phone
# #                 } for user in dish_view.user_likes
# #             ],
# #             "dish_image_url": data,
# #             "user_id": dish_view.user_id
# #         }
# #
# #         return {"recipes": serialized_dish}, 200
# #
# #
# # # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# #
#
# @dish.route("/d")
# class GetDishView(Resource):
#     def get(self):
#         dish_views = DishView.query.all()
#
#         serialized_dishes = []
#
#         for dish_view in dish_views:
#             data = base64.b64encode(dish_view.dish_image_url).decode("utf-8")
#
#             serialized_dish = {
#                 "id": dish_view.id,
#                 "name": dish_view.name,
#                 "instructions": dish_view.Instructions,
#                 "ingredients": dish_view.Ingredients,
#                 "date_posted": dish_view.date_posted.isoformat(),
#                 "user_likes": [
#                     {
#                         "id": user.id,
#                         "firstname": user.firstname,
#                         "lastname": user.lastname,
#                         "email": user.email,
#                         "phone": user.phone
#                     } for user in dish_view.user_likes
#                 ],
#                 "dish_image_url": data,
#                 "user_id": dish_view.user_id
#             }
#
#             serialized_dishes.append(serialized_dish)
#
#         return {"recipes": serialized_dishes}, 200
#
#
# # not working yet
# # Assuming DishView and UserSignUp models are defined and have appropriate fields
#
#
# @dish.route("/create-user-and-dish")
# class GetDishView(Resource):
#     def post(self):
#         data = request.get_json()
#         # Extract dish data from the request
#         name = data.get("name")
#         instructions = data.get("Instructions")
#         ingredients = data.get("Ingredients")
#         # dish_image_url = data.get("dish_image_url")
#
#
#         # convert image to base64
#         # if dish_image_url is None:
#         #     return {"Error": "Dish image URL is missing"}, 400
#         #
#         # try:
#         #     image64 = base64.b64decode(dish_image_url)
#         # except Exception as e:
#         #     return {"Error": "Invalid image data"}, 400
#
#         # Extract user data from the request
#         firstname = data.get("firstname")
#         lastname = data.get("lastname")
#         email = data.get("email")
#         password = data.get("password")
#         phone = data.get("phone")
#
#         # hash_password
#         # hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
#
#         # Create a new UserSignUp instance
#         new_user = Users(
#             firstname=firstname,
#             lastname=lastname,
#             email=email,
#             password=password,
#             phone=phone
#         )
#
#         # Create a new DishView instance
#         new_dish = DishView(
#             name=name,
#             Instructions=instructions,
#             Ingredients=ingredients,
#             # dish_image_url=image64,
#             date_posted=datetime.utcnow()
#         )
#
#         try:
#             # Add the new user and new dish to the session
#             db.session.add(new_user)
#             db.session.add(new_dish)
#
#             # Commit changes to the database
#             db.session.commit()
#
#             # Associate the new dish with the new user
#             new_dish.user = new_user
#             db.session.commit()
#
#             return {"message": "Dish and User created successfully!"}, 201
#         except Exception as e:
#             db.session.rollback()
#             return {"error": str(e)}, 500
