library api.github_hook;

import 'dart:async';
import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';
import 'package:shelf/shelf.dart';

import 'src/github_models.dart';

export 'src/github_models.dart';

typedef Future GitHubRequestHandler(HookRequest request);

const _eventHeader = 'x-github-event';
const _signatureHeader = 'x-github-delivery';

Handler createGitHubHookMiddleware(
    String secret, GitHubRequestHandler innerHandler) {
  return (Request request) async {
    // If it's not a POST, return a 405 - invalid method
    if (request.method != 'POST') {
      return new Response(405);
    }

    var githubDeliveryHeader = request.headers[_signatureHeader];

    if (githubDeliveryHeader == null) {
      return new Response(400, body: 'Missing the "$_signatureHeader" header.');
    }

    var signature = request.headers['x-hub-signature'];

    if (signature == null) {
      return new Response(403, body: 'Missing "$_signatureHeader" header.');
    }

    if (!signature.startsWith(_sha1Header)) {
      return new Response(403, body: 'Invalid "$_signatureHeader" header.');
    }

    var json;
    try {
      json = await _decodeJsonVerify(request.read(), secret, signature);
    } on BadSignatureError {
      return new Response(403, body: 'Invalid "x-hub-signature" header.');
    }

    var githubRequest = new HookRequest(
        request.headers[_eventHeader], request.headers[_signatureHeader], json);

    // If an error is thrown, it'll bubble down
    // ...and likely result in a 500 being sent back to GitHub
    await innerHandler(githubRequest);

    return new Response.ok('Thanks, GitHub!');
  };
}

class HookRequest {
  final Map<String, dynamic> content;

  final String githubEvent; // => shelfRequest.headers[_eventHeader];
  final String githubDelivery; // => shelfRequest.headers[_signatureHeader];

  HookRequest.core(this.githubEvent, this.githubDelivery, this.content);

  factory HookRequest(
      String githubEvent, String githubDelivery, Map<String, dynamic> content) {
    switch (githubEvent) {
      case 'issues':
        return new IssuesHookRequest(githubEvent, githubDelivery, content);
      default:
        return new HookRequest.core(githubEvent, githubDelivery, content);
    }
  }

  String toString() => 'GitHubHookRequest: $githubEvent $githubDelivery';
}

class IssuesHookRequest extends HookRequest {
  final String action;
  final Issue issue;
  final User sender;
  final Repository repository;
  final Label label;

  IssuesHookRequest(
      String githubEvent, String githubDelivery, Map<String, dynamic> content)
      : this.action = content['action'],
        this.issue = new Issue.fromJson(content['issue']),
        this.sender = new User.fromJson(content['sender']),
        this.repository = new Repository.fromJson(content['repository']),
        this.label = new Label.fromJson(content['label'], passNull: true),
        super.core(githubEvent, githubDelivery, content) {
    assert(githubEvent == 'issues');
  }

  String toString() => 'IssuesHookRequest: $action $githubDelivery';
}

class BadSignatureError extends ArgumentError {
  final String expectedSignature;
  final String actualSignature;

  String get message =>
      'The source has an HMAC of "$actualSignature", expected "$expectedSignature".';

  BadSignatureError(this.expectedSignature, this.actualSignature);

  String toString() => 'Bad signature: $message';
}

Future _decodeJsonVerify(
    Stream<List<int>> source, String secret, String expectedSha1) async {
  assert(expectedSha1.startsWith(_sha1Header));

  expectedSha1 = expectedSha1.substring(_sha1Header.length);

  assert(expectedSha1.length == 40);

  var secretBytes = UTF8.encode(secret);

  var hmac = new Hmac(sha1, secretBytes);
  var hmacSink = new AccumulatorSink<Digest>();
  var hmacByteSink = hmac.startChunkedConversion(hmacSink);

  var jsonSink = new AccumulatorSink();
  var jsonByteSink = _binaryJsonDecoder.startChunkedConversion(jsonSink);

  await for (var byteList in source) {
    hmacByteSink.add(byteList);
    jsonByteSink.add(byteList);
  }

  hmacByteSink.close();

  var resultSha1 = hex.encode(hmacSink.events.single.bytes);

  if (expectedSha1 != resultSha1) {
    throw new BadSignatureError(expectedSha1, resultSha1);
  }

  jsonByteSink.close();

  return jsonSink.events.single;
}

final _binaryJsonDecoder = UTF8.decoder.fuse(JSON.decoder);

const _sha1Header = 'sha1=';
