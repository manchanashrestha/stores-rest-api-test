from models.user import UserModel
from models.item import ItemModel
from models.store import StoreModel
from tests.existing_base_test import BaseTest
import json

class ItemTestTest(BaseTest):
    def setUp(self):
        super(ItemTestTest, self).setUp()
        with self.app() as client:
            with self.app_context():
                UserModel('test', '1234').save_to_db()
                auth_request = client.post('/auth',
                                           data= json.dumps({'username': 'test', 'password': '1234'}),
                                           headers={'Content-Type':'application/json'})
                auth_token = json.loads(auth_request.data)['access_token']
                self.access_token = f'JWT {auth_token}'

    # This method is throwing error sometimes
    def test_get_item_no_auth(self):
        with self.app() as client:
            with self.app_context():
                resp = client.get('/item/test')
                self.assertEqual(resp.status_code, 401)

    def test_get_item_not_found(self):
        with self.app() as client:
            with self.app_context():
                resp = client.get('/item/test', headers = {'Authorization': self.access_token})
                self.assertEqual(resp.status_code, 404)

    def test_get_item(self):
        with self.app() as client:
            with self.app_context():
                # StoreModel('test').save_to_db() --need to do it for SQL db
                ItemModel('test', 19.99, 1).save_to_db()
                resp = client.get('/item/test', headers = {'Authorization': self.access_token})
                self.assertEqual(resp.status_code, 200)

    def test_delete_item(self):
        with self.app() as client:
            with self.app_context():
                # StoreModel('test').save_to_db() --need to do it for SQL db
                ItemModel('test', 19.99, 1).save_to_db()

                resp = client.delete('/item/test')
                self.assertEqual(resp.status_code, 200)
                self.assertDictEqual({'message': 'Item deleted'},
                                     json.loads(resp.data))

    def test_create_item(self):
        with self.app() as client:
            with self.app_context():
                # StoreModel('test').save_to_db() --need to do it for SQL db

                resp = client.post('/item/test', data={'price': 19.99, 'store_id': 1})
                self.assertEqual(resp.status_code, 201)
                self.assertDictEqual({'name':'test','price':19.99},
                                    json.loads(resp.data))

    def test_create_duplicate_item(self):
        with self.app() as client:
            with self.app_context():
                # StoreModel('test').save_to_db() --need to do it for SQL db
                ItemModel('test', 19.99, 1).save_to_db()

                resp = client.post('/item/test', data={'price': 19.99, 'store_id': 1})
                self.assertEqual(resp.status_code, 400)
                self.assertDictEqual({'message': 'An item with name \'test\' already exists.'},
                                     json.loads(resp.data))

    def test_put_item(self):
        with self.app() as client:
            with self.app_context():
                # StoreModel('test').save_to_db() --need to do it for SQL db
                ItemModel('test', 19.99, 1).save_to_db()
                resp = client.put('/item/test', data={'price': 19.99, 'store_id': 1})

                self.assertEqual(resp.status_code, 200) # coz we can find item by name
                self.assertEqual(ItemModel.find_by_name('test').price, 19.99) # verify that the item can be find by name
                self.assertDictEqual({'name': 'test', 'price': 19.99},
                                     json.loads(resp.data)) # verifying that the data is correct

    def test_put_update_item(self):
        with self.app() as client:
            with self.app_context():
                # StoreModel('test').save_to_db() --need to do it for SQL db
                ItemModel('test', 5.99, 1).save_to_db() # inserting new data
                self.assertEqual(ItemModel.find_by_name('test').price, 5.99)
                resp = client.put('/item/test', data={'price': 19.99, 'store_id': 1}) # replacing existing data

                self.assertEqual(resp.status_code, 200)  # coz we can find item by name
                self.assertEqual(ItemModel.find_by_name('test').price,
                                 19.99)  # verify that the item can be find by name
                self.assertDictEqual({'name': 'test', 'price': 19.99},
                                     json.loads(resp.data))  # verifying that the data is correct


    def test_item_list(self):
        with self.app() as client:
            with self.app_context():
                # StoreModel('test').save_to_db() --need to do it for SQL db
                ItemModel('test', 5.99, 1).save_to_db() # inserting new data

                resp = client.get('/items')
                self.assertDictEqual({'items':[{'name':'test','price':5.99}]},
                                     json.loads(resp.data))

