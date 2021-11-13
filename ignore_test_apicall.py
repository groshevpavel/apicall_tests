import json
from pathlib import Path
from time import sleep
from unittest.mock import (
    patch,
    MagicMock,
)

import httpretty
import pytest
import requests
import responses
from requests import (
    Session,
    Response,
)

from bdp_dag_gluer.common.api_call import exceptions
from bdp_dag_gluer.common.api_call.middlewares.postprocessors import (
    raise_for_status,
    check_empty_response_body,
    json_or_error,
)
from bdp_dag_gluer.common.api_call.middlewares.preprocessors import prepare_request_id
from bdp_dag_gluer.common.api_call.requests import (
    HttpClient,
    ApiCall,
)
from tests.data.from_rest.mock_sources.dataversions import dataversions

MAIN_MOCK_URL = 'https://remote.rest.com/entities'
DATAVERSIONS_PATH = 'dataversions'


class TestHttpClient:
    @classmethod
    def setup_class(cls):
        cls.instance = HttpClient(url=MAIN_MOCK_URL)

    def test_instance(self):
        assert self.instance._url == MAIN_MOCK_URL
        assert self.instance._timeout is None

        assert isinstance(self.instance._session, Session)

    def test_prepare_session(self):
        auth = ('login', 'pass')
        headers_key = 'Content-Type'
        headers_value = 'application/json'
        cert = '/path/to/cert.key'

        instance_ = HttpClient(url=MAIN_MOCK_URL, auth=auth)
        assert instance_._session.auth == auth
        assert headers_key not in instance_._session.headers
        assert instance_._session.verify is True
        assert instance_._session.cert is None

        headers = {
            headers_key: headers_value
        }
        instance_ = HttpClient(url=MAIN_MOCK_URL, headers=headers)
        assert headers_key in instance_._session.headers
        assert instance_._session.headers[headers_key] == headers_value
        assert instance_._session.auth is None
        assert instance_._session.verify is True
        assert instance_._session.cert is None

        instance_ = HttpClient(url=MAIN_MOCK_URL, verify_ssl=False)
        assert instance_._session.verify is False
        assert instance_._session.auth is None
        assert headers_key not in instance_._session.headers
        assert instance_._session.cert is None

        instance_ = HttpClient(url=MAIN_MOCK_URL, cert=cert)
        assert instance_._session.cert == cert
        assert instance_._session.verify is True
        assert instance_._session.auth is None
        assert headers_key not in instance_._session.headers

    @pytest.mark.parametrize(
        'call_kwargs',
        [
            pytest.param({}, id='nodata, url compose'),
            # на случай различия заданного параметра и результата, на примере method=,
            # нужно дополнить словарь параметров вызова теста, параметром __res с альтернативным значением
            pytest.param(
                {'method': 'post', '__res': {'method': 'POST'}},
                id='post_method',
            ),
            pytest.param(
                {'data': {'key1': 'value1'}},
                id='data_param',
            ),
            pytest.param(
                {'json': '{"k": "value"}'},
                id='json_param',
            ),
            pytest.param(
                {'params': {'query_param1': 'val1'}},
                id='params_param',
            ),
            pytest.param(
                {'files': {'fn': (Path.cwd() / __file__).open()}},
                id='files_param',
            ),
            pytest.param(
                {'headers': {'X-MyOwnHeader': 'my_header_data'}},
                id='headers_param',
            ),
            pytest.param(
                {'auth': ('login', 'pass')},
                id='auth_param',
            ),
            pytest.param(
                {'timeout': 10},
                id='timeout_param',
            ),
        ],
    )
    @patch('requests.Session.request', autospec=True)
    def test_call(self, request_mock: MagicMock, call_kwargs: dict):
        result = call_kwargs.pop('__res') if '__res' in call_kwargs else call_kwargs

        self.instance.call(path=DATAVERSIONS_PATH, **call_kwargs)

        assert request_mock.called
        assert request_mock.call_count == 1

        assert isinstance(request_mock.call_args[0][0], requests.sessions.Session)
        assert request_mock.call_args[1] == {
            'url': f'{MAIN_MOCK_URL}/{DATAVERSIONS_PATH}',
            'method': 'GET',
            'data': None,
            'json': None,
            'headers': None,
            'auth': None,
            'params': None,
            'timeout': None,
            'files': None,
            **result,
        }


class TestApiCall:
    @classmethod
    def setup_class(cls):
        cls.dataversions_url = f'{MAIN_MOCK_URL}/{DATAVERSIONS_PATH}'
        cls.client = HttpClient(url=MAIN_MOCK_URL)

    def create_apicall(self, **kwargs) -> ApiCall:
        return ApiCall(client=self.client, **kwargs)

    def dataversions_apicall(self, add_path: str = '', **kwargs) -> ApiCall:
        return self.create_apicall(path=f'/{DATAVERSIONS_PATH}{add_path}', **kwargs)

    def test_apicall_blank(self, mocked_responses):
        mocked_responses.add(
            responses.GET,
            self.dataversions_url,
            json=dataversions,
        )

        apicall_dataversions = self.dataversions_apicall()
        response = apicall_dataversions()

        assert isinstance(response, Response)
        assert response.status_code == 200
        assert response.headers == {
            'Content-Type': 'application/json'
        }
        assert response.json() == dataversions

        assert apicall_dataversions._params == {
            'method': 'GET',
            'timeout': None,
            'auth': None
        }
        assert apicall_dataversions._path == '/dataversions'
        assert apicall_dataversions._client is self.client
        assert len(apicall_dataversions._handlers) == 1

        assert mocked_responses.assert_call_count(self.dataversions_url, 1)
        assert mocked_responses.calls[0].request.method == 'GET'
        assert mocked_responses.calls[0].request.url == self.dataversions_url

    def test_apicall_path_params(self, mocked_responses):
        def request_callback(request):
            dataversions_key = request.params['key']
            resp_body = dataversions[dataversions_key]

            return 200, {}, json.dumps(resp_body)

        mocked_responses.add_callback(
            responses.GET,
            self.dataversions_url,
            callback=request_callback,
            content_type='application/json',
        )

        keyname_to_recieve_in_response = 'RecognitionProtocolIntervals_TVI_ORB'

        add_path = '?key={dataversions_key}'
        apicall_dataversions = self.dataversions_apicall(add_path=add_path)
        response = apicall_dataversions(path_params={
            'dataversions_key': keyname_to_recieve_in_response
        })

        assert isinstance(response, Response)
        assert response.status_code == 200
        assert response.headers == {
            'Content-Type': 'application/json'
        }
        assert response.json() == dataversions[keyname_to_recieve_in_response]

        assert apicall_dataversions._path == '/dataversions?key={dataversions_key}'

        assert mocked_responses.assert_call_count(f'{self.dataversions_url}?key={keyname_to_recieve_in_response}', 1)
        assert mocked_responses.calls[0].request.method == 'GET'
        assert mocked_responses.calls[0].request.url == f'{self.dataversions_url}?key={keyname_to_recieve_in_response}'
        assert mocked_responses.calls[0].request.params == {
            'key': keyname_to_recieve_in_response
        }

    def test_apicall_method(self, mocked_responses):
        mocked_responses.add(
            responses.PUT,
            self.dataversions_url,
            json=dataversions,
        )

        apicall_dataversions = self.dataversions_apicall(method='PUT')
        response = apicall_dataversions()

        assert isinstance(response, Response)
        assert response.status_code == 200
        assert response.headers == {
            'Content-Type': 'application/json'
        }
        assert response.json() == dataversions

        assert mocked_responses.calls[0].request.method == 'PUT'

    @patch('bdp_dag_gluer.common.api_call.requests.requests.Session.request', autospec=True)
    def test_apicall_auth_timeout(self, request_mock):
        apicall_dataversions = self.dataversions_apicall(method='POST', timeout=1000, auth=('login', 'pass'))
        _ = apicall_dataversions()

        assert request_mock.call_count == 1
        request_mock.assert_called_with(self.client._session, **{
            'url': 'https://remote.rest.com/entities/dataversions',
            'method': 'POST',
            'data': None,
            'json': None,
            'headers': None,
            'auth': ('login', 'pass'),
            'params': None,
            'timeout': 1000,
            'files': None
        })

    @patch('bdp_dag_gluer.common.api_call.requests.requests.Session.request', autospec=True)
    def test_apicall_preprocessors(self, request_mock):
        apicall_dataversions = self.dataversions_apicall(preprocessors=[prepare_request_id])
        _ = apicall_dataversions()

        assert request_mock.call_count == 1
        assert request_mock.call_args[1]['headers'] is not None
        assert 'X-Request-Id' in request_mock.call_args[1]['headers']

        _ = apicall_dataversions(headers={'X-Request-Id': 'My-X-Request-Id'})

        assert request_mock.call_count == 2
        assert request_mock.call_args[1]['headers'] == {'X-Request-Id': 'My-X-Request-Id'}

    def test_apicall_postprocessors_all_ok(self, mocked_responses):
        def request_callback_200_ok(request):
            return 200, request.headers, json.dumps(dataversions)

        mocked_responses.add_callback(
            responses.GET,
            self.dataversions_url,
            callback=request_callback_200_ok,
            content_type='application/json',
        )

        apicall_dataversions = self.dataversions_apicall(
            postprocessors=[raise_for_status, check_empty_response_body, json_or_error],
        )
        response = apicall_dataversions()

        assert isinstance(response, dict)
        assert response == dataversions

    def test_apicall_preprocessors_postprocessors(self, mocked_responses):
        def request_callback_200_ok(request):
            return 200, request.headers, json.dumps(dataversions)

        mocked_responses.add_callback(
            responses.GET,
            self.dataversions_url,
            callback=request_callback_200_ok,
            content_type='application/json',
        )

        apicall_dataversions = self.dataversions_apicall(
            preprocessors=[prepare_request_id],
            postprocessors=[raise_for_status, check_empty_response_body],
        )
        response = apicall_dataversions()

        assert 'X-Request-Id' in response.headers
        assert response.headers['X-Request-Id'] != ''

        assert isinstance(response, Response)
        assert response.json() == dataversions

    def test_apicall_postprocessors_raise_for_status(self, mocked_responses):
        status_codes = iter([400, 401, 403, 404, 405, 500, 501, 402])

        def request_callback_bad(request):
            status_code = next(status_codes)
            return status_code, request.headers, f'{{"error": {status_code}}}'

        mocked_responses.add_callback(
            responses.GET,
            self.dataversions_url,
            callback=request_callback_bad,
            content_type='application/json',
        )

        apicall_dataversions = self.dataversions_apicall(
            postprocessors=[raise_for_status, check_empty_response_body, json_or_error],
        )

        statuscode_to_exception = [
            (400, exceptions.BadRequest),
            (401, exceptions.UnauthorizedError),
            (403, exceptions.AccessDeniedError),
            (404, exceptions.NotFoundError),
            (405, exceptions.MethodNotAllowedError),
            (500, exceptions.ExternalServiceError),
            (501, exceptions.ExternalServiceError),
            (402, exceptions.ExternalServiceError),
        ]
        for status_code, exception in statuscode_to_exception:
            with pytest.raises(exception) as exc:
                apicall_dataversions()

            assert exc.value.code == status_code
            assert exc.value.message == {'error': status_code}
            assert exc.value.detail == 'Remote URL: https://remote.rest.com/entities/dataversions'

    def test_apicall_postprocessors_empty_response(self, mocked_responses):
        def request_callback_bad(request):
            return 200, request.headers, ''

        mocked_responses.add_callback(
            responses.GET,
            self.dataversions_url,
            callback=request_callback_bad,
            content_type='application/json',
        )

        apicall_dataversions = self.dataversions_apicall(
            postprocessors=[raise_for_status, check_empty_response_body, json_or_error],
        )

        with pytest.raises(exceptions.ExternalServiceError) as exc:
            _ = apicall_dataversions()

        assert exc.value.code == 200
        assert exc.value.detail == 'Remote address: https://remote.rest.com/entities/dataversions return an empty response'

    def test_apicall_postprocessors_json_or_error(self, mocked_responses):
        def request_callback_bad(request):
            return 302, request.headers, '{\n\t"BAD_JSON_HERE\n\t}'

        mocked_responses.add_callback(
            responses.GET,
            self.dataversions_url,
            callback=request_callback_bad,
            content_type='application/json',
        )

        apicall_dataversions = self.dataversions_apicall(
            postprocessors=[raise_for_status, check_empty_response_body, json_or_error],
        )

        with pytest.raises(exceptions.ExternalServiceError) as exc:
            _ = apicall_dataversions()

        assert exc.value.code == 302
        assert 'caused json decode exception:' in exc.value.message


@httpretty.activate
class TestApiCallRetries:
    def register_uri_by_status_codes(self, status_codes):
        responses_list = [
            httpretty.Response(body='{"message": "HTTPretty :)"}', status=status_code)
            for status_code in status_codes
        ]
        httpretty.register_uri(
            httpretty.GET,
            f'{MAIN_MOCK_URL}/{DATAVERSIONS_PATH}',
            responses=responses_list,
        )

    def test_retry(self):
        status_codes = [500, 502, 503, 504, 200]
        self.register_uri_by_status_codes(status_codes)

        retry_config = {
            'total': 5,
            'connect': 3,
            'backoff_factor': 0.1,
        }
        client = HttpClient(url=MAIN_MOCK_URL, retry_config=retry_config)
        dataversions_apicall = ApiCall(client=client, path=f'/{DATAVERSIONS_PATH}')
        response = dataversions_apicall()

        assert len(httpretty.latest_requests()) == len(status_codes)
        assert response.status_code == 200
        assert response.url == 'https://remote.rest.com/entities/dataversions'

    def test_retries_exceeded(self):
        status_codes = [500, 502, 503, 504, 200]
        self.register_uri_by_status_codes(status_codes)

        retry_config = {
            'total': 3,
            'connect': 3,
            'backoff_factor': 0.1,
        }
        client = HttpClient(url=MAIN_MOCK_URL, retry_config=retry_config)
        dataversions_apicall = ApiCall(client=client, path=f'/{DATAVERSIONS_PATH}')

        with pytest.raises(requests.exceptions.RetryError):
            dataversions_apicall()

        assert len(httpretty.latest_requests()) == 4

    def test_timeout(self):
        def request_callback(request, uri, response_headers):
            sleep(1)
            return [200, response_headers, json.dumps({"hello": "world"})]

        httpretty.register_uri(
            httpretty.GET,
            f'{MAIN_MOCK_URL}/{DATAVERSIONS_PATH}',
            body=request_callback,
        )

        retry_config = {
            'total': 1,
            'connect': 1,
            'read': 1,
            'backoff_factor': 0.01,
        }
        client = HttpClient(url=MAIN_MOCK_URL, retry_config=retry_config, timeout=(2, 0.1))
        dataversions_apicall = ApiCall(client=client, path=f'/{DATAVERSIONS_PATH}')

        with pytest.raises(requests.exceptions.ConnectionError):
            dataversions_apicall()
