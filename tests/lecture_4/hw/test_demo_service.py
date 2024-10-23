from datetime import datetime
from datetime import timedelta
from typing import Any

import pytest
from starlette.testclient import TestClient

from lecture_4.demo_service.api.main import create_app
from lecture_4.demo_service.api.contracts import RegisterUserRequest, UserResponse, UserAuthRequest, SecretStr
from lecture_4.demo_service.core.users import UserInfo, UserService, UserEntity, UserRole, password_is_longer_than_8


def transform_user_info_to_dict(user_info: UserInfo) -> dict[str, Any]:
    request_dict = user_info.model_dump()
    request_dict["password"] = user_info.password.get_secret_value()
    request_dict["birthdate"] = user_info.birthdate.isoformat()
    return request_dict


demo_service = create_app()
client = TestClient(demo_service)

@pytest.fixture
def short_pass() -> SecretStr:
    return SecretStr("short")

@pytest.fixture
def long_pass() -> SecretStr:
    return SecretStr("long_password_123")

@pytest.fixture
def user_registration_request() -> RegisterUserRequest:
    return RegisterUserRequest(
        username="user",
        name="user",
        birthdate=datetime.now(),
        password=SecretStr("secret_password_123")
    )

@pytest.fixture
def user_info_fixture() -> UserInfo:
    return UserInfo(
        username="user",
        name="user",
        birthdate=datetime.now(),
        role=UserRole.USER,
        password="secret_password_123"
    )

@pytest.fixture
def admin_user_fixture() -> UserInfo:
    return UserInfo(
        username="admin",
        name="admin",
        birthdate=datetime.fromtimestamp(0.0),
        role=UserRole.ADMIN,
        password="superSecretAdminPassword123",
    )

@pytest.fixture
def user_with_bad_password(short_pass) -> UserInfo:
    return UserInfo(
        username="test",
        name="test",
        birthdate=datetime.fromtimestamp(0.0),
        role=UserRole.USER,
        password=short_pass,
    )

@pytest.fixture
def user_entity_fixture(user_info_fixture) -> UserEntity:
    return UserEntity(
        uid=1,
        info=user_info_fixture
    )

@pytest.fixture
def user_service_fixture(user_entity_fixture) -> UserService:
    return UserService()

@pytest.fixture
def user_response_fixture(user_entity_fixture) -> UserResponse:
    return UserResponse(
        uid=user_entity_fixture.uid,
        username=user_entity_fixture.info.username,
        name=user_entity_fixture.info.name,
        birthdate=user_entity_fixture.info.birthdate,
        role=user_entity_fixture.info.role
    )

@pytest.fixture
def auth_request() -> UserAuthRequest:
    return UserAuthRequest(
        username="user",
        password=SecretStr("secret_password_123")
    )

@pytest.fixture()
def test_client():
    demo_app = create_app()
    with TestClient(demo_app) as demo_app_client:
        yield demo_app_client


def test_password_length_validation(short_pass, long_pass):
    assert password_is_longer_than_8(long_pass) == True
    assert password_is_longer_than_8(short_pass) == False

def test_user_authentication(auth_request):
    assert auth_request.username == "user"
    assert auth_request.password.get_secret_value() == "secret_password_123"

def test_register_new_user(user_registration_request):
    assert user_registration_request.username == "user"
    assert user_registration_request.name == "user"
    assert user_registration_request.password.get_secret_value() == "secret_password_123"
    assert user_registration_request.birthdate > datetime.now() - timedelta(seconds=1)

def test_user_information(user_info_fixture):
    assert user_info_fixture.username == "user"
    assert user_info_fixture.name == "user"
    assert user_info_fixture.birthdate > datetime.now() - timedelta(seconds=1)
    assert user_info_fixture.password.get_secret_value() == "secret_password_123"
    assert user_info_fixture.role == UserRole.USER

def test_user_entity_info(user_entity_fixture, user_info_fixture):
    assert user_entity_fixture.uid == 1
    assert user_entity_fixture.info == user_info_fixture

def test_user_response_data(user_response_fixture, user_entity_fixture):
    assert user_response_fixture.uid == 1
    assert user_response_fixture.username == "user"
    assert user_response_fixture.name == "user"
    assert user_response_fixture.birthdate > datetime.now() - timedelta(seconds=1)
    assert user_response_fixture.role == UserRole.USER

    user_response_from_entity = UserResponse.from_user_entity(user_entity_fixture)
    assert user_response_from_entity.uid == 1
    assert user_response_from_entity.username == "user"
    assert user_response_from_entity.name == "user"
    assert user_response_from_entity.birthdate > datetime.now() - timedelta(seconds=1)
    assert user_response_from_entity.role == UserRole.USER

def test_user_service_methods(user_service_fixture, user_info_fixture):
    user_entity = user_service_fixture.register(user_info_fixture)
    assert user_entity.info.username == "user"
    assert user_entity.info.name == "user"
    assert user_entity.info.birthdate > datetime.now() - timedelta(seconds=1)
    assert user_entity.info.password.get_secret_value() == "secret_password_123"
    assert user_entity.info.role == UserRole.USER

    assert user_service_fixture.get_by_username(user_entity.info.username) == user_entity
    assert user_service_fixture.get_by_id(user_entity.uid) == user_entity

    user_service_fixture.grant_admin(user_entity.uid)
    assert user_service_fixture.get_by_id(user_entity.uid).info.role == UserRole.ADMIN

    with pytest.raises(ValueError):
        assert user_service_fixture.grant_admin('no_such_user')

    user_service_fixture.get_by_username("no_such_user") == None

def test_registration_with_bad_password(test_client, user_with_bad_password):
    request_data = transform_user_info_to_dict(user_with_bad_password)

    register_response = test_client.post("/user-register", json=request_data)
    assert register_response.status_code == 400

def test_successful_registration(test_client, user_registration_request):
    request_dict = transform_user_info_to_dict(user_registration_request)

    response = test_client.post("/user-register", json=request_dict)
    assert response.status_code == 200

    assert response.json()["username"] == user_registration_request.username
    assert response.json()["name"] == user_registration_request.name
    assert response.json()["birthdate"] == user_registration_request.birthdate.isoformat()
    assert response.json()["role"] == UserRole.USER.value

def test_get_user_info_as_user(test_client, user_registration_request, user_entity_fixture, user_response_fixture):
    request_data = transform_user_info_to_dict(user_registration_request)
    auth = (user_registration_request.username, user_registration_request.password.get_secret_value())

    register_response = test_client.post("/user-register", json=request_data)
    response = test_client.post("/user-get", params={'id': register_response.json()["uid"]}, auth=auth)

    assert response.status_code == 200
    assert response.json()["name"] == user_response_fixture.name
    assert response.json()["username"] == user_response_fixture.username
    assert response.json()["role"] == user_response_fixture.role
    assert datetime.fromisoformat(response.json()["birthdate"]) > user_response_fixture.birthdate - timedelta(seconds=1)

    response = test_client.post("/user-get", params={'id': user_entity_fixture.uid, 'username': user_entity_fixture.info.username}, auth=auth)
    assert response.status_code == 400

    response = test_client.post("/user-get", params={}, auth=auth)
    assert response.status_code == 400

    auth = (user_registration_request.username, "wrong_password")
    response = test_client.post("/user-get", params={'id': register_response.json().get("uid")}, auth=auth)
    assert response.status_code == 401

def test_get_user_info_as_admin(test_client, admin_user_fixture):
    admin_requets_dict = transform_user_info_to_dict(admin_user_fixture)
    admin_auth = (admin_user_fixture.username, admin_user_fixture.password.get_secret_value())

    test_client.post("/user-register", json=admin_requets_dict)
    response = test_client.post("/user-get", params={"username": "test"}, auth=admin_auth)
    assert response.status_code == 404

    test_client.post("/user-register", json=admin_requets_dict)
    response = test_client.post("/user-get", params={"username": "admin"}, auth=admin_auth)
    assert response.status_code == 200

def test_promote_user_as_regular_user(test_client, user_registration_request):
    request_data = transform_user_info_to_dict(user_registration_request)
    auth = (user_registration_request.username, user_registration_request.password.get_secret_value())

    register_response = test_client.post("/user-register", json=request_data)
    assert register_response.status_code == 200

    promote_response = test_client.post("/user-promote", params={'id': register_response.json()["uid"]}, auth=auth)
    assert promote_response.status_code == 403

def test_promote_user_as_admin(test_client, admin_user_fixture):
    admin_auth = (admin_user_fixture.username, admin_user_fixture.password.get_secret_value())

    promote_response = test_client.post("/user-promote", params={'id': "1"}, auth=admin_auth)
    assert promote_response.status_code == 200
