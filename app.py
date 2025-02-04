from os import getenv

from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwtы

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = getenv("JWT_SECRET_KEY")
jwt_manager = JWTManager(app)

# Пример данных
tours = [
    {"id": 1, "name": "Тайланд", "price": 100000},
    {"id": 2, "name": "Египет", "price": 120000}
]

users = {"frodo": "asd", "sam": "dsa"}

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username in users and users[username] == password:
        roles = "admin" if username == "frodo" else "user"
        # token = create_access_token(identity={"username": username, "roles": roles})
        token = create_access_token(identity=str(username), additional_claims={"roles": roles})  
        return make_response("success", "Токен создан", {"access_token": token})
    
    return make_response("error", "Неверный логин или пароль", status_code=401)

@app.route("/protected", methods=["GET"])
@jwt_required()
def protected_route():
    current_user = get_jwt_identity()
    return make_response("success", f"Добро пожаловать, {current_user}!")
    

@app.route("/admin", methods=["GET"])
@jwt_required()
def admin_route():
    user = get_jwt_identity()
    claims = get_jwt()
    if claims.get("roles") != "admin":
        return make_response("error", f"Доступ запрещён, {user}", status_code=403)
    return make_response("success", "Добро пожаловать, администратор!")

# Структура унифицированного ответа
def make_response(status, message, data=None, status_code=200):
    response = jsonify({
        "status": status,
        "message": message,
        "data": data
    })
    response.status_code = status_code
    return response

# Маршрут для получения тура по ID
@app.route("/api/tours/<int:tour_id>", methods=["GET"])
def get_tour(tour_id):
    # Найти тур в списке, где id совпадает с переданным tour_id
    for tour in tours:
        if tour["id"] == tour_id:  # Если id совпадает
            return make_response("success", "Тур найден", tour)  # Возвращаем найденный тур в формате JSON

    # Если тур не найден
    return make_response("error", "Тур не найден", status_code=404)

# Получить все туры
@app.route("/api/tours", methods=["GET"])
def get_tours():
    return make_response("success", "Показаны все направления", tours)

# Редактирование тура
@app.route("/api/tours/<int:tour_id>", methods=["PUT"])
def update_tour(tour_id):
    if request.content_type != "application/json":
        return make_response("error", "Неверный тип контента. Ожидается application/json", status_code=400)

    data = request.get_json()

    for tour in tours:
        if tour["id"] == tour_id:  # Если id совпадает
            tour["name"] = data.get("name", tour["name"])  # Обновляем название
            tour["price"] = data.get("price", tour["price"])  # Обновляем цену
            return make_response("success", "Тур отредактирован", tour)  # Возвращаем обновленный тур

    # Если тур не найден
    return make_response("error", "Тур не найден", status_code=404)

# Создание нового тура
@app.route("/api/tours", methods=["POST"])
def create_tour():
    if request.content_type != "application/json":
        return make_response("error", "Неверный тип контента. Ожидается application/json", status_code=400)

    data = request.get_json()

    # Проверка входных данных
    if not data or not data.get("name") or not data.get("price"):
        return make_response("error", "Название и цена обязательны", status_code=404)

    # Создание нового тура
    new_tour = {
        "id": len(tours) + 1,  # Генерация нового ID
        "name": data["name"],
        "price": data["price"],
    }
    tours.append(new_tour)  # Добавление в список туров
    return make_response("success", "Тур создан", new_tour)

# Удаление тура
@app.route("/api/tours/<int:tour_id>", methods=["DELETE"])
def delete_tour(tour_id):
    global tours
    tour_to_delete = next((tour for tour in tours if tour["id"] == tour_id), None)

    tour_name = tour_to_delete["name"]
    tours = [t for t in tours if t["id"] != tour_id] # Удаляем тур с переданным id
    return make_response("success", f"Тур '{tour_name}' удалён"), 202 # Возвращаем подтверждение с кодом 202
    
# Обработка ошибок
@app.errorhandler(500)
def handle_500_error(e):
    return make_response("error", "Что-то пошло не так на сервере", status_code=500)

@app.errorhandler(404)
def handle_404_error(e):
    return make_response("error", "Ресурс не найден", status_code=404)

if __name__ == "__main__":
    app.run(debug=True)
