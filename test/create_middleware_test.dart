import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';
import 'package:github_hook/github_hook.dart';
import 'package:shelf/shelf.dart';
import 'package:test/test.dart';

import 'test_util.dart';

const _secret = 'Îñţérñåţîöñåļîžåţîờñ';

final _rootUri = Uri.parse('http://localhost/');
final _neverWinHandler = createGitHubHookMiddleware(_secret, (body) {
  throw 'Should never get here...';
});

void main() {
  test('valid request continues', () async {
    var handler =
        createGitHubHookMiddleware(_secret, (HookRequest request) async {
      expect(request.content, _dummyPayload);
    });

    var requestBody = JSON.encode(_dummyPayload);

    var sha = _getSha1Hmac(requestBody, _secret);

    var headers = {
      "x-github-delivery": "87292380-152d-11e5-9f54-f82c72f79efc",
      "x-hub-signature": "sha1=${sha}"
    };

    var request =
        new Request('POST', _rootUri, body: requestBody, headers: headers);

    var response = await handler(request);

    var body = await response.readAsString();

    expect(body, 'Thanks, GitHub!');
    expect(response.statusCode, 200);
  });

  test('valid issues request', () async {
    var handler =
        createGitHubHookMiddleware(_secret, (IssuesHookRequest request) async {
      expect(request.action, 'opened');
    });

    var sha = _getSha1Hmac(issueOpenedBody, _secret);

    var headers = {
      "x-github-event": "issues",
      "x-github-delivery": "87292380-152d-11e5-9f54-f82c72f79efc",
      "x-hub-signature": "sha1=${sha}"
    };

    var request =
        new Request('POST', _rootUri, body: issueOpenedBody, headers: headers);

    var response = await handler(request);

    var body = await response.readAsString();

    expect(body, 'Thanks, GitHub!');
    expect(response.statusCode, 200);
  });

  group('invalid hook request fails', () {
    test('non-post', () async {
      var request = new Request('GET', _rootUri);

      var response = await _neverWinHandler(request);

      expect(response.statusCode, 405);
    });

    test('missing x-github-delivery header', () async {
      var request = new Request('POST', _rootUri);

      var response = await _neverWinHandler(request);

      expect(response.statusCode, 400);

      var body = await response.readAsString();

      expect(body, 'Missing the "x-github-delivery" header.');
    });

    test('missing signature fails', () async {
      var requestBody = JSON.encode(_dummyPayload);

      var headers = {
        "x-github-delivery": "87292380-152d-11e5-9f54-f82c72f79efc"
      };

      var request =
          new Request('POST', _rootUri, body: requestBody, headers: headers);

      var response = await _neverWinHandler(request);

      expect(response.statusCode, 403);

      var body = await response.readAsString();

      expect(body, 'Missing "x-github-delivery" header.');
    });

    test('invalid signature fails', () async {
      var requestBody = JSON.encode(_dummyPayload);

      var sha = _getSha1Hmac(requestBody, 'bad secret');

      var headers = {
        "x-github-delivery": "87292380-152d-11e5-9f54-f82c72f79efc",
        "x-hub-signature": "sha1=${sha}"
      };

      var request =
          new Request('POST', _rootUri, body: requestBody, headers: headers);

      var response = await _neverWinHandler(request);

      expect(response.statusCode, 403);

      var body = await response.readAsString();

      expect(body, 'Invalid "x-hub-signature" header.');
    });
  });
}

String _getSha1Hmac(String content, String _secret) {
  var bytes = _getHmac(content, _secret);

  return hex.encode(bytes);
}

List<int> _getHmac(String content, String secret) {
  var hmac = new Hmac(sha1, UTF8.encode(secret));

  return hmac.convert(UTF8.encode(content)).bytes;
}

const _dummyPayload = const {
  "id": 243908268,
  "sha": "125288670f25fc0da5df4c72081e6c669d09d401",
  "name": "dart-lang/dartdoc",
  "target_url": "https://travis-ci.org/dart-lang/dartdoc/builds/67262433",
  "context": "continuous-integration/travis-ci/push",
  "description": "The Travis CI build passed"
};

const _sampleHeader = const {
  "user-agent": "GitHub-Hookshot/becf8d8",
  "accept": "*/*",
  "x-github-delivery": "5510c500-151f-11e5-98c5-e4f7af0a4a35",
  "content-length": "8576",
  "host": "146.148.88.122:8080",
  "content-type": "application/json",
  "x-github-event": "issues",
  "x-hub-signature": "sha1=5298218b2f0f3bbfdb5af80bade8f68a8e99948d"
};
