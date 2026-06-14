import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' show Random;
import 'package:flutter_rust_bridge/flutter_rust_bridge.dart' show Uint64List;
import 'package:app_links/app_links.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show rootBundle;
import 'package:http/http.dart' as http;
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:path_provider/path_provider.dart';
import 'package:url_launcher/url_launcher.dart';

import 'package:mopro_flutter_bindings/src/rust/frb_generated.dart';

import 'credential_page.dart';
import 'package:mopro_flutter_bindings/src/rust/third_party/openac_mobile_app.dart'
    show
        BenchmarkResults,
        ProofResult,
        ZkProofError,
        generatePrepareInput,
        generateShowInput,
        generateSharedBlinds,
        proveJwt,
        proveShow,
        reblindJwt,
        reblindShow,
        runCompleteBenchmark,
        verifyJwt,
        verifyShow;

final GlobalKey<NavigatorState> _navigatorKey = GlobalKey<NavigatorState>();

Future<String> _zkErrorMessage(dynamic e) async =>
    e is ZkProofError ? await e.message() : e.toString();

// Set just before launching the government wallet so the returning deep link
// can carry the verifier's transaction ID through to CredentialPage.
String? _pendingTransactionId;

// Set when a VP token arrives from the MODA wallet (in _extractAndPrepare).
// These are used by _generateAndWriteShowInput() to prove real device binding.
// _pendingVpSigningInput = "{header_b64}.{payload_b64}" (JWT signing input)
// _pendingVpDeviceSig   = base64url ES256 signature over SHA-256(signing_input)
String? _pendingVpSigningInput;
String? _pendingVpDeviceSig;

// Real vc+sd-jwt — issuer-vc.wallet.gov.tw, kid key-1, alg ES256.
// Type: 00000000_vpms_20250605. cnf.jwk: x=H32qvUPZeG…, y=5sPwNmz2MR…
// Issuer public key "key-1" coordinates (decimal); verified against the live JWK Set.
const String _kIssuerPubkeyX =
    '53578245562568858090497762971050088637552636662548898700080252253957930675571';
const String _kIssuerPubkeyY =
    '94717717123739987908966931526384127659809793164315839803856846695569747893398';
const String _kCredentialJwt =
    'eyJqa3UiOiJodHRwczovL2lzc3Vlci12Yy53YWxsZXQuZ292LnR3L2FwaS9rZXlzIiwia2lkIjoia2V5LTEiLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9'
    '.eyJzdWIiOiJkaWQ6a2V5OnoyZG16RDgxZDFBQ21ISENza0xnNUNuVmVxVkZHVTc4VmJMWWplQ1dzRXhEenlqNDI5RVNnNGZyQjI0b2tXSmdoNlN1TFVnMWR4OWg1NFBFNWdITXRY'
    'THV5aWg3UlRheXg4QUZWY241VUNRRFpIQkNoWUNUQ1FIeFl5cnhxN21FSkd3TEdGUFJ6cUJLV3k2VUUxcmFQRTZDSkVlVzVQd295cnpqU0x0NUMxVFZhaTVxdWUiLCJuYmYiOjE3ODA1'
    'Nzg4NTQsImlzcyI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticlRRV1BUSk10MkZ1MTZIODR5bXdiYkc5TEdOaW5XN1luajUz'
    'WkNBVzE2Z3JBaEJpd3Y1M0FuYnY3ODdodDZueGFLTUdHQWdZOVdqdEZ4WVozaGpHZE1kMVNodVFvU3ZOZVh4Y2o1SmNiazJ1WXRmR2J3aW9GU2laUVhmekg3Y3RoaSIsImNuZiI6eyJq'
    'd2siOnsieCI6IkgzMnF2VVBaZUdfWllqbzlZdmVVWDFQZDNQelI1M3VvamFiRTFMTW9VbTAiLCJjcnYiOiJQLTI1NiIsInkiOiI1c1B3Tm16Mk1Sd2pVemZYN1BNb25aaW95Vk5yN0pf'
    'SlZ1V2dSRnRpX3o0Iiwia3R5IjoiRUMifX0sImV4cCI6NDkwNDcxNjQ1NCwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwi'
    'dHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIjAwMDAwMDAwX3ZwbXNfMjAyNTA2MDUiXSwiY3JlZGVudGlhbFN0YXR1cyI6eyJ0eXBlIjoiU3RhdHVzTGlzdDIwMjFFbnRyeSIs'
    'ImlkIjoiaHR0cHM6Ly9pc3N1ZXItdmMud2FsbGV0Lmdvdi50dy9hcGkvc3RhdHVzLWxpc3QvMDAwMDAwMDBfdnBtc18yMDI1MDYwNS9yMCM2MSIsInN0YXR1c0xpc3RJbmRleCI6IjYx'
    'Iiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwczovL2lzc3Vlci12Yy53YWxsZXQuZ292LnR3L2FwaS9zdGF0dXMtbGlzdC8wMDAwMDAwMF92cG1zXzIwMjUwNjA1L3IwIiwic3Rh'
    'dHVzUHVycG9zZSI6InJldm9jYXRpb24ifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vZnJvbnRlbmQud2FsbGV0Lmdvdi50dy9hcGkvc2NoZW1hLzAwMDAwMDAwL3Zw'
    'bXMyMDI1MDYwNS9WMS9lYjYzODQxMi0zMGU3LTRlODYtYTRjNi1mMjg4ZGEyZjRkNjMiLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJfc2QiOlsiLXNt'
    'Um9TRzd0UDBhRmQzcmM1dWFWRTZpSkk5ZFRuZW5TTk11QVV5dURYNCIsIjRRZkdrdWR1N2xaWDJoRTNBb1FkOFY3YmJZUVVzeFRPYVpSWmRKWmtWcjgiLCJNTGZsOUE5ZjNHR0pjZDNf'
    'NEZ1LVU5YnEzZUZWOUFPS1BwQjQzWkNYel9RIiwiWjc5bi1Ed0tuZDhReHpoMFB2YzNfNV9TZ0ZmenpLcUxMUjhlZUx6NkFwcyIsIno0bUhWS2NqdmZ0YWVoaE5OZUQxVFU4V2x2WkF0'
    'U1dxVV9NbGRmZGpWZFUiXSwiX3NkX2FsZyI6InNoYS0yNTYifX0sIm5vbmNlIjoiMlk1QVJNM1EiLCJqdGkiOiJodHRwczovL2lzc3Vlci12Yy53YWxsZXQuZ292LnR3L2FwaS9jcmVk'
    'ZW50aWFsL2U3YjY3NWZmLTRkNDAtNDIzMi04NThkLWUwYTNjMjVhM2I2ZCJ9'
    '.R_T5Kp1CvTHigJkZGxoANTvfH3NI-JdAIe8s2jwxrFg8gT13psr4VuAL8i5ALQewMQ5NIMBgzdiKeq1sWNgEZw';

// ── QR Code Parsing (mirrors iOS ParseLinkManager) ──────────────────────────

enum QrResultType { parseVC, parseVP, staticVC, staticVP, error }

class QrParseResult {
  final QrResultType type;
  final String? data;
  final String? errorMessage;
  const QrParseResult({required this.type, this.data, this.errorMessage});
}

QrParseResult _parseQrCodeUrl(String text) {
  final uri = Uri.tryParse(text);
  if (uri == null) return QrParseResult(type: QrResultType.error, errorMessage: 'Invalid URL');
  if (uri.scheme == 'https') return _handleUniversalLink(uri);
  if (uri.scheme == 'modadigitalwallet') return _handleDeepLink(uri);
  return QrParseResult(type: QrResultType.error, errorMessage: 'Unknown scheme: ${uri.scheme}');
}

QrParseResult _handleUniversalLink(Uri uri) {
  final mode = uri.queryParameters['mode'];
  if (mode == null) return QrParseResult(type: QrResultType.error, errorMessage: 'Missing mode');
  if (uri.path == '/api/moda/qrcode') {
    if (mode == 'vc') return QrParseResult(type: QrResultType.staticVC, data: uri.queryParameters['vcUid'] ?? '');
    if (mode == 'vp') return QrParseResult(type: QrResultType.staticVP, data: uri.queryParameters['vpUid'] ?? '');
  } else if (uri.path == '/api/moda/vcqrcode' && mode == 'vc01') {
    return QrParseResult(type: QrResultType.parseVC, data: _decodeDeeplink(uri.queryParameters['deeplink'] ?? ''));
  } else if (uri.path == '/api/moda/vpqrcode' && mode == 'vp01') {
    return QrParseResult(type: QrResultType.parseVP, data: _decodeDeeplink(uri.queryParameters['deeplink'] ?? ''));
  }
  return QrParseResult(type: QrResultType.error, errorMessage: 'Unrecognized path/mode: ${uri.path}?mode=$mode');
}

QrParseResult _handleDeepLink(Uri uri) {
  if (uri.host == 'credential_offer') return QrParseResult(type: QrResultType.parseVC, data: uri.toString());
  if (uri.host == 'authorize') return QrParseResult(type: QrResultType.parseVP, data: uri.toString());
  return QrParseResult(type: QrResultType.error, errorMessage: 'Unknown host: ${uri.host}');
}

// Decodes URL-safe base64-encoded deeplink parameter (matches iOS decodeInnerDeeplink).
String _decodeDeeplink(String encoded) {
  try {
    final decoded = Uri.decodeComponent(encoded);
    final standard = decoded.replaceAll('-', '+').replaceAll('_', '/');
    final rem = standard.length % 4;
    final padded = rem == 0 ? standard : standard + '=' * (4 - rem);
    return utf8.decode(base64Decode(padded));
  } catch (_) {
    return encoded;
  }
}


Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  await _copyAssetsToDocuments();
  runApp(const MyApp());
}

/// Copy circuit files from Flutter assets into the app's documents directory,
/// mirroring the layout used by Rust's PathConfig::mobile:
///
///   {docs}/circom/build/jwt/jwt_js/jwt.r1cs   ← decompressed from jwt.r1cs.gz
///   {docs}/circom/build/show/show_js/show.r1cs ← decompressed from show.r1cs.gz
///   {docs}/keys/prepare_proving.key            ← decompressed from 4k_prepare_proving.key.gz
///   {docs}/keys/prepare_verifying.key          ← decompressed from 4k_prepare_verifying.key.gz
///   {docs}/keys/show_proving.key               ← decompressed from 4k_show_proving.key.gz
///   {docs}/keys/show_verifying.key             ← decompressed from 4k_show_verifying.key.gz
Future<void> _copyAssetsToDocuments() async {
  try {
    final documentsDir = await getApplicationDocumentsDirectory();
    final circomDir = Directory('${documentsDir.path}/circom');
    final keysDir = Directory('${documentsDir.path}/keys');

    final jwtBuildDir = Directory('${circomDir.path}/build/jwt/jwt_js');
    final showBuildDir = Directory('${circomDir.path}/build/show/show_js');
    await jwtBuildDir.create(recursive: true);
    await showBuildDir.create(recursive: true);
    await keysDir.create(recursive: true);

    final compressedAssets = {
      'assets/circom/jwt.r1cs.gz': '${jwtBuildDir.path}/jwt.r1cs',
      'assets/circom/show.r1cs.gz': '${showBuildDir.path}/show.r1cs',
      'assets/keys/4k_prepare_proving.key.gz': '${keysDir.path}/prepare_proving.key',
      'assets/keys/4k_prepare_verifying.key.gz': '${keysDir.path}/prepare_verifying.key',
      'assets/keys/4k_show_proving.key.gz': '${keysDir.path}/show_proving.key',
      'assets/keys/4k_show_verifying.key.gz': '${keysDir.path}/show_verifying.key',
    };
    for (final entry in compressedAssets.entries) {
      final target = File(entry.value);
      if (!await target.exists()) {
        debugPrint('Decompressing ${entry.key}');
        final data = await rootBundle.load(entry.key);
        final decompressed = gzip.decode(data.buffer.asUint8List());
        await target.writeAsBytes(decompressed);
        debugPrint(
            '  → ${(decompressed.length / 1024 / 1024).toStringAsFixed(2)} MB');
      }
    }

  } catch (e) {
    debugPrint('Error copying assets: $e');
  }
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      navigatorKey: _navigatorKey,
      debugShowCheckedModeBanner: false,
      theme: ThemeData(primarySwatch: Colors.blue, useMaterial3: true),
      home: const E2EProofWorkflowScreen(),
    );
  }
}

class E2EProofWorkflowScreen extends StatefulWidget {
  const E2EProofWorkflowScreen({super.key});

  @override
  State<E2EProofWorkflowScreen> createState() =>
      _E2EProofWorkflowScreenState();
}

enum ProofTaskType {
  generateBlinds,
  proveJwt,
  proveShow,
  reblindJwt,
  reblindShow,
  verifyJwt,
  verifyShow,
}

class TaskResult {
  final ProofTaskType taskType;
  final bool success;
  final String? error;
  final ProofResult? proofResult;
  final String? message;
  final bool? verifyResult;
  final int? clientTimingMs;

  TaskResult({
    required this.taskType,
    required this.success,
    this.error,
    this.proofResult,
    this.message,
    this.verifyResult,
    this.clientTimingMs,
  });

  BigInt? get totalMs =>
      proofResult?.totalMs ??
      (clientTimingMs != null ? BigInt.from(clientTimingMs!) : null);
  BigInt? get proofSizeBytes => proofResult?.proofSizeBytes;
  String? get commWShared => proofResult?.commWShared;
}

class _E2EProofWorkflowScreenState extends State<E2EProofWorkflowScreen> {
  bool _isOperating = false;
  Exception? _error;

  Map<String, TaskResult> _results = {};
  Map<String, bool> _completedSteps = {};
  BenchmarkResults? _benchmarkResults;

  bool _workflowRunning = false;
  String? _currentWorkflowStep;

  bool _generatingInput = false;
  String? _prepareInputStatus;
  String? _prepareInputError;

  bool _generatingShowInput = false;
  String? _showInputStatus;
  String? _showInputError;

  StreamSubscription<Uri>? _linkSub;

  @override
  void initState() {
    super.initState();
    _initDeepLinks();
  }

  @override
  void dispose() {
    _linkSub?.cancel();
    super.dispose();
  }

  Future<void> _initDeepLinks() async {
    final appLinks = AppLinks();
    // Handle the link that launched the app cold.
    final initial = await appLinks.getInitialLink();
    if (initial != null) _handleIncomingLink(initial);
    // Handle links while the app is already running.
    _linkSub = appLinks.uriLinkStream.listen(_handleIncomingLink);
  }

  void _handleIncomingLink(Uri uri) {
    if (uri.scheme != 'openac') return;
    if (uri.host != 'zkproof') return;
    final vc = uri.queryParameters['vc'];
    if (vc == null || vc.isEmpty) return;
    final txId = _pendingTransactionId;
    _pendingTransactionId = null;
    debugPrint('[DeepLink] received sdJwt length=${vc.length}, txId=$txId');
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      Navigator.of(context).push(MaterialPageRoute(
        builder: (_) => CredentialPage(sdJwt: vc, transactionId: txId),
      ));
    });
  }

  Future<String> _getDocumentsPath() async {
    final dir = await getApplicationDocumentsDirectory();
    return dir.path;
  }

  Future<TaskResult> _executeStep(
      ProofTaskType taskType, String documentsPath) async {
    switch (taskType) {
      case ProofTaskType.generateBlinds:
        final t = DateTime.now();
        final msg = await generateSharedBlinds(documentsPath: documentsPath);
        return TaskResult(
          taskType: taskType,
          success: true,
          message: msg,
          clientTimingMs: DateTime.now().difference(t).inMilliseconds,
        );

      case ProofTaskType.proveJwt:
        final pr = await proveJwt(documentsPath: documentsPath);
        return TaskResult(taskType: taskType, success: true, proofResult: pr);

      case ProofTaskType.proveShow:
        final pr = await proveShow(documentsPath: documentsPath);
        return TaskResult(taskType: taskType, success: true, proofResult: pr);

      case ProofTaskType.reblindJwt:
        final pr = await reblindJwt(documentsPath: documentsPath);
        return TaskResult(taskType: taskType, success: true, proofResult: pr);

      case ProofTaskType.reblindShow:
        final pr = await reblindShow(documentsPath: documentsPath);
        return TaskResult(taskType: taskType, success: true, proofResult: pr);

      case ProofTaskType.verifyJwt:
        final t = DateTime.now();
        final ok = await verifyJwt(documentsPath: documentsPath);
        return TaskResult(
          taskType: taskType,
          success: ok,
          verifyResult: ok,
          clientTimingMs: DateTime.now().difference(t).inMilliseconds,
        );

      case ProofTaskType.verifyShow:
        final t = DateTime.now();
        final ok = await verifyShow(documentsPath: documentsPath);
        return TaskResult(
          taskType: taskType,
          success: ok,
          verifyResult: ok,
          clientTimingMs: DateTime.now().difference(t).inMilliseconds,
        );
    }
  }

  Future<void> _generateAndWritePrepareInput() async {
    setState(() {
      _generatingInput = true;
      _prepareInputStatus = null;
      _prepareInputError = null;
    });
    try {
      final docs = await _getDocumentsPath();
      final jsonStr = await generatePrepareInput(
        jwt: _kCredentialJwt,
        issuerPubkeyX: _kIssuerPubkeyX,
        issuerPubkeyY: _kIssuerPubkeyY,
      );
      await File('$docs/jwt_input.json').writeAsString(jsonStr);
      final data = jsonDecode(jsonStr) as Map<String, dynamic>;
      setState(() {
        _prepareInputStatus =
            'messageLength=${data['messageLength']}  '
            'periodIndex=${data['periodIndex']}  '
            'matchesCount=${data['matchesCount']}';
        _generatingInput = false;
      });
    } catch (e) {
      setState(() {
        _prepareInputError = e.toString();
        _generatingInput = false;
      });
    }
  }

  // Synthetic test vectors from circom/inputs/show/4k/default.json.
  // The Show circuit verifies device-key possession (ECDSA over nonce hash) independently
  // from the JWT's cnf.jwk; a valid proof requires the matching device private key, which
  // is unavailable here. These pre-computed values satisfy all 4k circuit constraints.
  static const _kTestShowInput = {
    'deviceKeyX': '3235469921824929619667006482855853611393970393649187893408674476281226521848',
    'deviceKeyY': '76077612271780672660977489200716927494983953737189345678969020897162074805789',
    'sig_r': '32294691588770405271110282100373162390371747761899034323693438388417848650884',
    'sig_s_inverse': '17410881328306032428067187457454160326934099535867317817093755989428511695672',
    'messageHash': '103112455607070190239702750162666382343409356112044643088145721996033151411339',
    'predicateLen': '1',
    'claimValues': ['1040605', '0'],
    'predicateClaimRefs': ['0', '0'],
    'predicateOps': ['0', '2'],
    'predicateRhsIsRef': ['0', '0'],
    'predicateRhsValues': ['1070101', '1040605'],
    'tokenTypes': ['0', '0', '0', '0', '0', '0', '0', '0'],
    'tokenValues': ['0', '0', '0', '0', '0', '0', '0', '0'],
    'exprLen': '1',
  };

  Future<void> _generateAndWriteShowInput() async {
    setState(() {
      _generatingShowInput = true;
      _showInputStatus = null;
      _showInputError = null;
    });
    try {
      final docs = await _getDocumentsPath();
      final vpSigningInput = _pendingVpSigningInput;
      final vpDeviceSig = _pendingVpDeviceSig;

      String jsonStr;
      if (vpSigningInput != null && vpDeviceSig != null) {
        // Use real VP JWT device binding — nonce = VP JWT signing input.
        jsonStr = await generateShowInput(
          jwt: _kCredentialJwt,
          deviceSignature: vpDeviceSig,
          nonce: vpSigningInput,
          claimValues: ['0', '0'],
          predicateLen: BigInt.zero,
          predicateClaimRefs: Uint64List.fromList([0, 0]),
          predicateOps: Uint64List.fromList([0, 0]),
          predicateRhsIsRef: Uint64List.fromList([0, 0]),
          predicateRhsValues: ['0', '0'],
          exprLen: BigInt.zero,
          tokenTypes: Uint64List.fromList([0, 0, 0, 0, 0, 0, 0, 0]),
          tokenValues: Uint64List.fromList([0, 0, 0, 0, 0, 0, 0, 0]),
        );
        await File('$docs/show_input.json').writeAsString(jsonStr);
        final data = jsonDecode(jsonStr) as Map<String, dynamic>;
        final devKeyX = (data['deviceKeyX'] as String?)?.substring(0, 8) ?? '?';
        final msgHash = (data['messageHash'] as String?)?.substring(0, 8) ?? '?';
        setState(() {
          _showInputStatus = '[real VP JWT] devKeyX=$devKeyX…  msgHash=$msgHash…';
          _generatingShowInput = false;
        });
      } else {
        // Fall back to pre-computed 4k test vectors when no VP token is available.
        jsonStr = jsonEncode(_kTestShowInput);
        await File('$docs/show_input.json').writeAsString(jsonStr);
        setState(() {
          _showInputStatus =
              '[test vectors] devKeyX=${(_kTestShowInput['deviceKeyX'] as String).substring(0, 8)}…  '
              'msgHash=${(_kTestShowInput['messageHash'] as String).substring(0, 8)}…';
          _generatingShowInput = false;
        });
      }
    } catch (e) {
      final msg = await _zkErrorMessage(e);
      setState(() {
        _showInputError = msg;
        _generatingShowInput = false;
      });
    }
  }

  Future<void> _runOperation(ProofTaskType taskType) async {
    setState(() {
      _isOperating = true;
      _error = null;
    });
    try {
      final docs = await _getDocumentsPath();
      final result = await _executeStep(taskType, docs);
      setState(() {
        _results[taskType.name] = result;
        _completedSteps[taskType.name] = result.success;
        _isOperating = false;
      });
    } catch (e) {
      final msg = await _zkErrorMessage(e);
      setState(() {
        _results[taskType.name] =
            TaskResult(taskType: taskType, success: false, error: msg);
        _completedSteps[taskType.name] = false;
        _error = Exception('${_taskTypeToDisplayName(taskType)} failed: $msg');
        _isOperating = false;
      });
    }
  }

  /// Full 11-step pipeline: generate inputs → setup → blinds → prove/reblind → verify.
  Future<void> _runE2EWorkflow() async {
    setState(() {
      _isOperating = true;
      _workflowRunning = true;
      _error = null;
      _results = {};
      _completedSteps = {};
      _prepareInputStatus = null;
      _prepareInputError = null;
      _showInputStatus = null;
      _showInputError = null;
      _currentWorkflowStep = null;
    });

    // Step 1a: Generate prepare input
    setState(() => _currentWorkflowStep = '1/9: Generate Prepare Input');
    await _generateAndWritePrepareInput();
    if (_prepareInputError != null) {
      setState(() {
        _error = Exception('Pipeline stopped: Generate Prepare Input failed');
        _isOperating = false;
        _workflowRunning = false;
        _currentWorkflowStep = null;
      });
      return;
    }

    // Step 1b: Generate show input
    setState(() => _currentWorkflowStep = '2/9: Generate Show Input');
    await _generateAndWriteShowInput();
    if (_showInputError != null) {
      setState(() {
        _error = Exception('Pipeline stopped: Generate Show Input failed');
        _isOperating = false;
        _workflowRunning = false;
        _currentWorkflowStep = null;
      });
      return;
    }

    final docs = await _getDocumentsPath();
    const steps = [
      ProofTaskType.generateBlinds,
      ProofTaskType.proveJwt,
      ProofTaskType.reblindJwt,
      ProofTaskType.proveShow,
      ProofTaskType.reblindShow,
      ProofTaskType.verifyJwt,
      ProofTaskType.verifyShow,
    ];

    for (int i = 0; i < steps.length; i++) {
      final step = steps[i];
      setState(() {
        _currentWorkflowStep =
            '${i + 3}/9: ${_taskTypeToDisplayName(step)}';
      });
      try {
        final result = await _executeStep(step, docs);
        setState(() {
          _results[step.name] = result;
          _completedSteps[step.name] = result.success;
        });
        if (!result.success) {
          setState(() {
            _error = Exception(
                'Pipeline stopped: ${_taskTypeToDisplayName(step)} failed');
            _isOperating = false;
            _workflowRunning = false;
            _currentWorkflowStep = null;
          });
          return;
        }
      } catch (e) {
        final msg = await _zkErrorMessage(e);
        setState(() {
          _results[step.name] =
              TaskResult(taskType: step, success: false, error: msg);
          _completedSteps[step.name] = false;
          _error = Exception(
              'Pipeline stopped at ${_taskTypeToDisplayName(step)}: $msg');
          _isOperating = false;
          _workflowRunning = false;
          _currentWorkflowStep = null;
        });
        return;
      }
    }

    setState(() {
      _isOperating = false;
      _workflowRunning = false;
      _currentWorkflowStep = null;
    });
  }

  Future<void> _runBenchmark() async {
    setState(() {
      _isOperating = true;
      _error = null;
      _benchmarkResults = null;
    });
    try {
      final docs = await _getDocumentsPath();
      final results = await runCompleteBenchmark(documentsPath: docs);
      setState(() {
        _benchmarkResults = results;
        _isOperating = false;
      });
    } catch (e) {
      setState(() {
        _error = Exception('Benchmark failed: $e');
        _isOperating = false;
      });
    }
  }

  void _reset() {
    setState(() {
      _results = {};
      _completedSteps = {};
      _error = null;
      _isOperating = false;
      _benchmarkResults = null;
      _workflowRunning = false;
      _currentWorkflowStep = null;
      _prepareInputStatus = null;
      _prepareInputError = null;
      _showInputStatus = null;
      _showInputError = null;
    });
  }

  String _taskTypeToDisplayName(ProofTaskType type) {
    return switch (type) {
      ProofTaskType.generateBlinds => 'Generate Shared Blinds',
      ProofTaskType.proveJwt => 'Prove JWT',
      ProofTaskType.proveShow => 'Prove Show',
      ProofTaskType.reblindJwt => 'Reblind JWT',
      ProofTaskType.reblindShow => 'Reblind Show',
      ProofTaskType.verifyJwt => 'Verify JWT',
      ProofTaskType.verifyShow => 'Verify Show',
    };
  }

  // ── Step completion helpers ──────────────────────────────────────────────

  bool get _step1Complete =>
      _prepareInputStatus != null && _showInputStatus != null;
  bool get _step2Complete => _completedSteps['generateBlinds'] == true;
  bool get _step3Complete =>
      _completedSteps['proveJwt'] == true &&
      _completedSteps['reblindJwt'] == true;
  bool get _step4Complete =>
      _completedSteps['proveShow'] == true &&
      _completedSteps['reblindShow'] == true;
  bool get _step5Complete =>
      _completedSteps['verifyJwt'] == true &&
      _completedSteps['verifyShow'] == true;

  // ── Build ────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('zkID Proof Pipeline'),
        actions: [
          if (!_isOperating)
            IconButton(
              icon: const Icon(Icons.refresh),
              onPressed: _reset,
              tooltip: 'Reset',
            ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            if (_error != null) _buildErrorBanner(),
            _buildQuickActions(),
            const SizedBox(height: 20),
            _buildStep(
              step: 1,
              title: 'Generate Inputs',
              icon: Icons.input,
              color: Colors.cyan.shade700,
              completed: _step1Complete,
              child: _buildStep1Content(),
            ),
            _buildConnector(),
            _buildStep(
              step: 2,
              title: 'Generate Shared Blinds',
              icon: Icons.shuffle,
              color: Colors.orange.shade700,
              completed: _step2Complete,
              child: _buildOperationButton(
                taskType: ProofTaskType.generateBlinds,
                label: 'Generate Shared Blinds',
                icon: Icons.shuffle,
                color: Colors.orange,
              ),
            ),
            _buildConnector(),
            _buildStep(
              step: 3,
              title: 'JWT Proof',
              icon: Icons.assignment,
              color: Colors.green.shade700,
              completed: _step3Complete,
              child: Row(
                children: [
                  Expanded(
                    child: _buildOperationButton(
                      taskType: ProofTaskType.proveJwt,
                      label: 'Prove JWT',
                      icon: Icons.calculate,
                      color: Colors.green,
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: _buildOperationButton(
                      taskType: ProofTaskType.reblindJwt,
                      label: 'Reblind JWT',
                      icon: Icons.sync,
                      color: Colors.green,
                    ),
                  ),
                ],
              ),
            ),
            _buildConnector(),
            _buildStep(
              step: 4,
              title: 'Show Proof',
              icon: Icons.visibility,
              color: Colors.deepPurple.shade700,
              completed: _step4Complete,
              child: Row(
                children: [
                  Expanded(
                    child: _buildOperationButton(
                      taskType: ProofTaskType.proveShow,
                      label: 'Prove Show',
                      icon: Icons.calculate,
                      color: Colors.deepPurple,
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: _buildOperationButton(
                      taskType: ProofTaskType.reblindShow,
                      label: 'Reblind Show',
                      icon: Icons.sync,
                      color: Colors.deepPurple,
                    ),
                  ),
                ],
              ),
            ),
            _buildConnector(),
            _buildStep(
              step: 5,
              title: 'Verify Proofs',
              icon: Icons.check_circle,
              color: Colors.teal.shade700,
              completed: _step5Complete,
              child: Row(
                children: [
                  Expanded(
                    child: _buildOperationButton(
                      taskType: ProofTaskType.verifyJwt,
                      label: 'Verify JWT',
                      icon: Icons.check_circle,
                      color: Colors.teal,
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: _buildOperationButton(
                      taskType: ProofTaskType.verifyShow,
                      label: 'Verify Show',
                      icon: Icons.check_circle,
                      color: Colors.teal,
                    ),
                  ),
                ],
              ),
            ),
            if (_results.isNotEmpty) ...[
              const SizedBox(height: 28),
              const Divider(),
              const SizedBox(height: 12),
              Row(
                children: [
                  Icon(Icons.assessment, color: Colors.grey.shade700),
                  const SizedBox(width: 8),
                  Text('Results',
                      style: TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                          color: Colors.grey.shade800)),
                ],
              ),
              const SizedBox(height: 12),
              ..._results.entries.map((e) => _buildResultCard(e.key, e.value)),
            ],
            if (_benchmarkResults != null) ...[
              const SizedBox(height: 16),
              _buildBenchmarkResults(),
            ],
            const SizedBox(height: 24),
          ],
        ),
      ),
    );
  }

  // ── Quick Actions ────────────────────────────────────────────────────────

  Widget _buildErrorBanner() {
    return Card(
      color: Colors.red.shade50,
      margin: const EdgeInsets.only(bottom: 16),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Row(
          children: [
            Icon(Icons.error, color: Colors.red.shade700),
            const SizedBox(width: 8),
            Expanded(
              child: Text(_error.toString(),
                  style: TextStyle(color: Colors.red.shade900)),
            ),
            IconButton(
              icon: const Icon(Icons.close),
              onPressed: () => setState(() => _error = null),
              padding: EdgeInsets.zero,
              constraints: const BoxConstraints(),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildQuickActions() {
    return Card(
      elevation: 3,
      color: Colors.indigo.shade50,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Row(
              children: [
                Icon(Icons.rocket_launch, color: Colors.indigo),
                SizedBox(width: 8),
                Text('Quick Actions',
                    style:
                        TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
              ],
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  flex: 3,
                  child: ElevatedButton.icon(
                    onPressed: _isOperating ? null : _runE2EWorkflow,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.indigo,
                      foregroundColor: Colors.white,
                      padding: const EdgeInsets.all(14),
                    ),
                    icon: _workflowRunning
                        ? const SizedBox(
                            width: 18,
                            height: 18,
                            child: CircularProgressIndicator(
                              strokeWidth: 2,
                              valueColor:
                                  AlwaysStoppedAnimation<Color>(Colors.white),
                            ),
                          )
                        : const Icon(Icons.play_circle_filled),
                    label: Text(_workflowRunning
                        ? 'Running…'
                        : 'Run Full Pipeline (11 steps)'),
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  flex: 2,
                  child: ElevatedButton.icon(
                    onPressed: _isOperating ? null : _runBenchmark,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.deepPurple,
                      foregroundColor: Colors.white,
                      padding: const EdgeInsets.all(14),
                    ),
                    icon: const Icon(Icons.speed),
                    label: const Text('Benchmark'),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 10),
            Row(
              children: [
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: _isOperating
                        ? null
                        : () => Navigator.of(context).push(
                              MaterialPageRoute(builder: (_) => const QrScannerScreen()),
                            ),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.teal,
                      foregroundColor: Colors.white,
                      padding: const EdgeInsets.all(14),
                    ),
                    icon: const Icon(Icons.qr_code_scanner),
                    label: const Text('Scan QR Code'),
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: _isOperating
                        ? null
                        : () => launchUrl(
                              Uri.parse(_kModaVpQrUrl),
                              mode: LaunchMode.externalApplication,
                            ),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.deepPurple,
                      foregroundColor: Colors.white,
                      padding: const EdgeInsets.all(14),
                    ),
                    icon: const Icon(Icons.wallet),
                    label: const Text('MODA Wallet'),
                  ),
                ),
              ],
            ),
            if (_workflowRunning && _currentWorkflowStep != null) ...[
              const SizedBox(height: 10),
              Row(
                children: [
                  const SizedBox(
                    width: 14,
                    height: 14,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  ),
                  const SizedBox(width: 8),
                  Text(
                    _currentWorkflowStep!,
                    style: TextStyle(
                        fontSize: 13,
                        fontWeight: FontWeight.w500,
                        color: Colors.indigo.shade700),
                  ),
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }

  // ── Step card shell ──────────────────────────────────────────────────────

  Widget _buildStep({
    required int step,
    required String title,
    required IconData icon,
    required Color color,
    required bool completed,
    required Widget child,
  }) {
    return Card(
      elevation: 2,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: completed
            ? BorderSide(color: color, width: 1.5)
            : BorderSide(color: Colors.grey.shade200),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                CircleAvatar(
                  radius: 14,
                  backgroundColor: completed ? color : Colors.grey.shade300,
                  child: Text(
                    '$step',
                    style: TextStyle(
                      color: completed ? Colors.white : Colors.grey.shade600,
                      fontSize: 12,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
                const SizedBox(width: 10),
                Icon(icon, color: color, size: 20),
                const SizedBox(width: 8),
                Text(
                  title,
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Colors.grey.shade800,
                  ),
                ),
                if (completed) ...[
                  const Spacer(),
                  Icon(Icons.check_circle, color: color, size: 18),
                ],
              ],
            ),
            const SizedBox(height: 14),
            child,
          ],
        ),
      ),
    );
  }

  Widget _buildConnector() {
    return Center(
      child: Container(
        width: 2,
        height: 20,
        color: Colors.grey.shade300,
      ),
    );
  }

  // ── Step 1: Generate Inputs ──────────────────────────────────────────────

  Widget _buildStep1Content() {
    final busy = _isOperating || _generatingInput || _generatingShowInput;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _buildInputButton(
          label: 'Generate Prepare Input',
          isLoading: _generatingInput,
          isDone: _prepareInputStatus != null,
          status: _prepareInputStatus,
          error: _prepareInputError,
          color: Colors.cyan.shade700,
          onPressed: busy ? null : _generateAndWritePrepareInput,
        ),
        const SizedBox(height: 10),
        _buildInputButton(
          label: 'Generate Show Input',
          isLoading: _generatingShowInput,
          isDone: _showInputStatus != null,
          status: _showInputStatus,
          error: _showInputError,
          color: Colors.teal.shade700,
          onPressed: busy ? null : _generateAndWriteShowInput,
        ),
      ],
    );
  }

  Widget _buildInputButton({
    required String label,
    required bool isLoading,
    required bool isDone,
    required String? status,
    required String? error,
    required Color color,
    required VoidCallback? onPressed,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        ElevatedButton.icon(
          onPressed: onPressed,
          style: ElevatedButton.styleFrom(
            backgroundColor: isDone ? color.withValues(alpha: 0.12) : color,
            foregroundColor: isDone ? color : Colors.white,
            padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 16),
          ),
          icon: isLoading
              ? SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    valueColor: AlwaysStoppedAnimation<Color>(
                        isDone ? color : Colors.white),
                  ),
                )
              : Icon(isDone ? Icons.check_circle : Icons.upload_file),
          label: Text(isLoading ? 'Generating…' : label),
        ),
        if (status != null) ...[
          const SizedBox(height: 6),
          Row(
            children: [
              Icon(Icons.check_circle, color: Colors.green.shade600, size: 14),
              const SizedBox(width: 4),
              Expanded(
                child: Text(
                  status,
                  style: TextStyle(
                    fontSize: 11,
                    color: Colors.green.shade700,
                    fontFamily: 'monospace',
                  ),
                ),
              ),
            ],
          ),
        ],
        if (error != null) ...[
          const SizedBox(height: 6),
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(Icons.error, color: Colors.red.shade600, size: 14),
              const SizedBox(width: 4),
              Expanded(
                child: Text(error,
                    style: TextStyle(fontSize: 11, color: Colors.red.shade700)),
              ),
            ],
          ),
        ],
      ],
    );
  }

  // ── Proof operation buttons ──────────────────────────────────────────────

  Widget _buildOperationButton({
    required ProofTaskType taskType,
    required String label,
    required IconData icon,
    required MaterialColor color,
  }) {
    final isCompleted = _completedSteps[taskType.name] == true;
    final result = _results[taskType.name];

    return ElevatedButton.icon(
      onPressed: _isOperating ? null : () => _runOperation(taskType),
      style: ElevatedButton.styleFrom(
        backgroundColor: isCompleted ? color.shade100 : color,
        foregroundColor: isCompleted ? color.shade900 : Colors.white,
        padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 16),
      ),
      icon: isCompleted
          ? Icon(Icons.check_circle, color: color.shade700)
          : Icon(icon),
      label: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(label),
          if (result?.totalMs != null)
            Text(
              '${result!.totalMs}ms',
              style: TextStyle(
                fontSize: 11,
                color: isCompleted ? color.shade700 : Colors.white70,
              ),
            ),
        ],
      ),
    );
  }

  // ── Result cards ─────────────────────────────────────────────────────────

  Widget _buildResultCard(String taskName, TaskResult result) {
    final taskType =
        ProofTaskType.values.firstWhere((e) => e.name == taskName);
    final displayName = _taskTypeToDisplayName(taskType);

    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  result.success ? Icons.check_circle : Icons.error,
                  color: result.success ? Colors.green : Colors.red,
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(displayName,
                      style: const TextStyle(
                          fontSize: 16, fontWeight: FontWeight.bold)),
                ),
              ],
            ),
            const SizedBox(height: 12),
            if (result.error != null) ...[
              Text('Error: ${result.error}',
                  style: TextStyle(color: Colors.red.shade700)),
              const SizedBox(height: 8),
            ],
            if (result.message != null) ...[
              Text(result.message!),
              const SizedBox(height: 8),
            ],
            if (result.totalMs != null) ...[
              const Text('Timing:',
                  style: TextStyle(fontWeight: FontWeight.bold)),
              const SizedBox(height: 4),
              Text('• Total: ${result.totalMs}ms'),
              const SizedBox(height: 8),
            ],
            if (result.proofSizeBytes != null) ...[
              Text(
                'Proof Size: ${(result.proofSizeBytes!.toInt() / 1024).toStringAsFixed(2)} KB',
                style: TextStyle(color: Colors.grey.shade700),
              ),
              const SizedBox(height: 8),
            ],
            if (result.commWShared != null) ...[
              const Text('Shared Commitment:',
                  style: TextStyle(fontWeight: FontWeight.bold)),
              const SizedBox(height: 4),
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: Colors.grey.shade100,
                  borderRadius: BorderRadius.circular(4),
                ),
                child: SelectableText(
                  result.commWShared!,
                  style: TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12,
                    color: Colors.grey.shade800,
                  ),
                ),
              ),
            ],
            if (result.verifyResult != null) ...[
              const SizedBox(height: 8),
              Text(
                result.verifyResult!
                    ? 'Verification passed ✓'
                    : 'Verification failed ✗',
                style: TextStyle(
                  color: result.verifyResult!
                      ? Colors.green.shade700
                      : Colors.red.shade700,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  // ── Benchmark results ────────────────────────────────────────────────────

  Widget _buildBenchmarkResults() {
    if (_benchmarkResults == null) return const SizedBox.shrink();
    final r = _benchmarkResults!;

    return Card(
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                const Row(
                  children: [
                    Icon(Icons.assessment, color: Colors.deepPurple),
                    SizedBox(width: 8),
                    Text('Benchmark Results',
                        style: TextStyle(
                            fontSize: 18, fontWeight: FontWeight.bold)),
                  ],
                ),
                IconButton(
                  icon: const Icon(Icons.close, size: 20),
                  onPressed: () => setState(() => _benchmarkResults = null),
                  tooltip: 'Clear results',
                ),
              ],
            ),
            const SizedBox(height: 16),
            const Text('Timing Metrics',
                style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Colors.deepPurple)),
            const SizedBox(height: 8),
            Table(
              border: TableBorder.all(color: Colors.grey.shade300),
              columnWidths: const {
                0: FlexColumnWidth(2),
                1: FlexColumnWidth(1),
              },
              children: [
                _tableHeader(['Operation', 'Time (ms)']),
                _timingRow('JWT Setup', r.jwtSetupMs),
                _timingRow('Show Setup', r.showSetupMs),
                _timingRow('Generate Blinds', r.generateBlindsMs),
                _timingRow('Prove JWT', r.proveJwtMs),
                _timingRow('Reblind JWT', r.reblindJwtMs),
                _timingRow('Prove Show', r.proveShowMs),
                _timingRow('Reblind Show', r.reblindShowMs),
                _timingRow('Verify JWT', r.verifyJwtMs),
                _timingRow('Verify Show', r.verifyShowMs),
              ],
            ),
            const SizedBox(height: 24),
            const Text('Artifact Sizes',
                style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Colors.deepPurple)),
            const SizedBox(height: 8),
            Table(
              border: TableBorder.all(color: Colors.grey.shade300),
              columnWidths: const {
                0: FlexColumnWidth(2),
                1: FlexColumnWidth(1),
              },
              children: [
                _tableHeader(['Artifact', 'Size']),
                _sizeRow('JWT Proving Key', r.jwtProvingKeyBytes),
                _sizeRow('JWT Verifying Key', r.jwtVerifyingKeyBytes),
                _sizeRow('Show Proving Key', r.showProvingKeyBytes),
                _sizeRow('Show Verifying Key', r.showVerifyingKeyBytes),
                _sizeRow('JWT Proof', r.jwtProofBytes),
                _sizeRow('Show Proof', r.showProofBytes),
                _sizeRow('JWT Witness', r.jwtWitnessBytes),
                _sizeRow('Show Witness', r.showWitnessBytes),
              ],
            ),
          ],
        ),
      ),
    );
  }

  TableRow _tableHeader(List<String> headers) {
    return TableRow(
      decoration: BoxDecoration(color: Colors.grey.shade200),
      children: headers
          .map((h) => Padding(
                padding: const EdgeInsets.all(8),
                child: Text(h,
                    style: const TextStyle(
                        fontWeight: FontWeight.bold, fontSize: 14)),
              ))
          .toList(),
    );
  }

  TableRow _timingRow(String op, BigInt ms) {
    return TableRow(children: [
      Padding(padding: const EdgeInsets.all(8), child: Text(op)),
      Padding(
        padding: const EdgeInsets.all(8),
        child: Text(ms.toString(),
            style: const TextStyle(fontFamily: 'monospace'),
            textAlign: TextAlign.right),
      ),
    ]);
  }

  TableRow _sizeRow(String artifact, BigInt bytes) {
    final b = bytes.toInt();
    final formatted = b < 1024
        ? '$b B'
        : b < 1024 * 1024
            ? '${(b / 1024).toStringAsFixed(2)} KB'
            : '${(b / (1024 * 1024)).toStringAsFixed(2)} MB';
    return TableRow(children: [
      Padding(padding: const EdgeInsets.all(8), child: Text(artifact)),
      Padding(
        padding: const EdgeInsets.all(8),
        child: Text(formatted,
            style: const TextStyle(fontFamily: 'monospace'),
            textAlign: TextAlign.right),
      ),
    ]);
  }
}

// ── MODA wallet VP QR URL (UAT) ──────────────────────────────────────────────
const _kModaVpQrUrl =
    'https://frontend-uat.wallet.gov.tw/api/moda/vpqrcode?mode=vp01&deeplink=bW9kYWRpZ2l0YWx3YWxsZXQ6Ly9hdXRob3JpemU/Y2xpZW50X2lkPWRpZCUzQWtleSUzQXoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYnBpazRRZmRUY1k0RFNabVZwNkZudHVjNm9GNmpxS1RLSDJublNZdUVZQ1NIdEhFeXZWNDRVWnc0TmNlRW5vdjJlWUw1ZWprcFZzVnk3Q2dGZjhZalgxVkpGNVNBR0ZBV3R4NlRpYmdwaEp0RDY0aDY3NHFIZ3hmUmFnRjZUeGpMblkmcmVxdWVzdF91cmk9aHR0cHMlM0ElMkYlMkZyZXF1ZXN0LWxvZy12aWV3ZXIudml2aTQzMjIyLndvcmtlcnMuZGV2JTJGdHdkaXctdWF0';

// ── QR Scanner Screen ────────────────────────────────────────────────────────

const _kVerifierBaseUrl = 'https://verifier-sandbox.wallet.gov.tw';
const _kVerifierHeaders = {
  'accept': '*/*',
  'Access-Token': 'JXkJnhep7Cy11F74yoy5ea69xcOmwXfP',
  'content-type': 'application/json',
};

String _newUuid() {
  final r = Random.secure();
  final b = List.generate(16, (_) => r.nextInt(256));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  final s = b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
  return '${s.substring(0, 8)}-${s.substring(8, 12)}-${s.substring(12, 16)}-${s.substring(16, 20)}-${s.substring(20)}';
}

// Appends openac_callback=openac://zkproof and launches the wallet deep link.
Future<void> _launchInWallet(String authUri) async {
  Uri? base;
  final qrResult = _parseQrCodeUrl(authUri);
  if (qrResult.type != QrResultType.error && qrResult.data != null) {
    base = Uri.tryParse(qrResult.data!);
  }
  base ??= Uri.tryParse(authUri);
  if (base == null) return;
  final walletUri = base.replace(queryParameters: {
    ...base.queryParameters,
    'openac_callback': 'openac://zkproof',
  });
  await launchUrl(walletUri, mode: LaunchMode.externalApplication);
}

class QrScannerScreen extends StatefulWidget {
  const QrScannerScreen({super.key});

  @override
  State<QrScannerScreen> createState() => _QrScannerScreenState();
}

class _QrScannerScreenState extends State<QrScannerScreen> {
  final MobileScannerController _controller = MobileScannerController();
  bool _processing = false;
  String? _error;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _onDetect(BarcodeCapture capture) async {
    if (_processing) return;
    final raw = capture.barcodes.firstOrNull?.rawValue;
    if (raw == null || raw.isEmpty) return;
    await _handleQrData(raw);
  }

  // Parses QR data from OpenACVerifier.tsx format: "ref=REF&transactionId=UUID".
  // Also accepts full URLs that contain those params.
  ({String ref, String transactionId})? _parseQrPayload(String raw) {
    // Try as bare query string first.
    final fromQuery = Uri.tryParse('x://x?$raw');
    final r1 = fromQuery?.queryParameters['ref'];
    final t1 = fromQuery?.queryParameters['transactionId'];
    if (r1 != null && t1 != null) return (ref: r1, transactionId: t1);

    // Fallback: treat as a full URL.
    final fromUrl = Uri.tryParse(raw);
    final r2 = fromUrl?.queryParameters['ref'];
    final t2 = fromUrl?.queryParameters['transactionId'];
    if (r2 != null && t2 != null) return (ref: r2, transactionId: t2);

    return null;
  }

  Future<void> _handleQrData(String raw) async {
    setState(() {
      _processing = true;
      _error = null;
    });
    await _controller.stop();

    try {
      final parsed = _parseQrPayload(raw);
      if (parsed == null) {
        // Try as a MODA VP QR (vpqrcode with embedded request_uri).
        final qrResult = _parseQrCodeUrl(raw);
        if (qrResult.type == QrResultType.parseVP && qrResult.data != null) {
          final deeplink = Uri.tryParse(qrResult.data!);
          final requestUri = deeplink?.queryParameters['request_uri'];
          if (requestUri != null) {
            if (!mounted) return;
            setState(() => _processing = false);
            await Navigator.of(context).push(MaterialPageRoute(
              builder: (_) => _OpenCredProofScreen(
                walletDeeplink: qrResult.data!,
                requestUri: requestUri,
              ),
            ));
            if (mounted) await _controller.start();
            return;
          }
        }
        throw Exception(
            'QR code does not contain ref and transactionId.\nGot: $raw');
      }

      // walletTxId is a fresh UUID separate from the scanned openacTransactionId.
      final walletTxId = _newUuid();

      if (!mounted) return;
      setState(() => _processing = false);

      await Navigator.of(context).push(MaterialPageRoute(
        builder: (_) => _QrConfirmScreen(
          ref: parsed.ref,
          openacTransactionId: parsed.transactionId,
          walletTxId: walletTxId,
        ),
      ));

      // Restart camera if user came back without launching.
      if (mounted) await _controller.start();
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _processing = false;
        _error = e.toString();
      });
      await _controller.start();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Scan QR Code')),
      body: Stack(
        children: [
          MobileScanner(
            controller: _controller,
            onDetect: _onDetect,
          ),

          // Viewfinder frame
          if (!_processing)
            Center(
              child: Container(
                width: 240,
                height: 240,
                decoration: BoxDecoration(
                  border: Border.all(color: Colors.white70, width: 2.5),
                  borderRadius: BorderRadius.circular(16),
                ),
              ),
            ),

          // Hint text
          if (!_processing)
            Positioned(
              bottom: 80,
              left: 0,
              right: 0,
              child: Text(
                'Point at the OpenAC verifier QR code',
                textAlign: TextAlign.center,
                style: const TextStyle(
                    color: Colors.white,
                    fontSize: 15,
                    shadows: [Shadow(blurRadius: 4, color: Colors.black54)]),
              ),
            ),

          // Processing overlay
          if (_processing)
            Container(
              color: Colors.black54,
              child: const Center(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    CircularProgressIndicator(color: Colors.white),
                    SizedBox(height: 16),
                    Text(
                      'Fetching auth request…',
                      style: TextStyle(color: Colors.white, fontSize: 16),
                    ),
                  ],
                ),
              ),
            ),

          // Error banner
          if (_error != null)
            Positioned(
              bottom: 32,
              left: 20,
              right: 20,
              child: Card(
                color: Colors.red.shade50,
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12)),
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Row(
                    children: [
                      Icon(Icons.error_outline,
                          color: Colors.red.shade700, size: 20),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(_error!,
                            style: TextStyle(
                                color: Colors.red.shade800, fontSize: 13)),
                      ),
                    ],
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }
}

// ── QR Confirm Screen ─────────────────────────────────────────────────────────

class _QrConfirmScreen extends StatefulWidget {
  final String ref;
  final String openacTransactionId;
  final String walletTxId;

  const _QrConfirmScreen({
    required this.ref,
    required this.openacTransactionId,
    required this.walletTxId,
  });

  @override
  State<_QrConfirmScreen> createState() => _QrConfirmScreenState();
}

class _QrConfirmScreenState extends State<_QrConfirmScreen> {
  bool _fetchingRequest = true;
  bool _launching = false;
  String? _error;
  String? _authUri;

  @override
  void initState() {
    super.initState();
    _fetchAuthRequest();
  }

  Future<void> _fetchAuthRequest() async {
    setState(() {
      _fetchingRequest = true;
      _error = null;
    });
    try {
      final res = await http.get(
        Uri.parse(
            '$_kVerifierBaseUrl/api/oidvp/qrcode?ref=${widget.ref}&transactionId=${widget.walletTxId}'),
        headers: _kVerifierHeaders,
      );
      if (res.statusCode != 200) throw Exception('HTTP ${res.statusCode}');
      final json = jsonDecode(res.body) as Map<String, dynamic>;
      final uri = json['authUri'] as String?;
      if (uri == null) throw Exception('No authUri in response');
      if (!mounted) return;
      setState(() {
        _authUri = uri;
        _fetchingRequest = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _fetchingRequest = false;
        _error = e.toString();
      });
    }
  }

  Future<void> _openInWallet() async {
    if (_authUri == null) return;
    setState(() {
      _launching = true;
      _error = null;
    });
    try {
      _pendingTransactionId = widget.openacTransactionId;
      await _launchInWallet(_authUri!);
      if (mounted) Navigator.of(context).popUntil((route) => route.isFirst);
    } catch (e) {
      if (!mounted) return;
      _pendingTransactionId = null;
      setState(() {
        _launching = false;
        _error = e.toString();
      });
    }
  }

  String _credentialLabel(String ref) {
    if (ref.contains('driver_license')) return 'Taiwan Driver License';
    if (ref.contains('demo')) return 'Demo Credential';
    return ref;
  }

  @override
  Widget build(BuildContext context) {
    if (_fetchingRequest) {
      return Scaffold(
        appBar: AppBar(title: const Text('Verification Request')),
        body: const Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              CircularProgressIndicator(),
              SizedBox(height: 16),
              Text('Fetching verification request…',
                  style: TextStyle(fontSize: 15)),
            ],
          ),
        ),
      );
    }

    return Scaffold(
      appBar: AppBar(title: const Text('Verification Request')),
      body: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // ── Header ───────────────────────────────────────────
            Card(
              color: Colors.indigo.shade50,
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(16)),
              child: Padding(
                padding: const EdgeInsets.symmetric(
                    horizontal: 16, vertical: 20),
                child: Column(
                  children: [
                    Icon(Icons.policy_outlined,
                        color: Colors.indigo.shade700, size: 40),
                    const SizedBox(height: 8),
                    Text(
                      'Credential Verification Request',
                      style: TextStyle(
                          fontSize: 17,
                          fontWeight: FontWeight.bold,
                          color: Colors.indigo.shade800),
                      textAlign: TextAlign.center,
                    ),
                    const SizedBox(height: 4),
                    Text(
                      'A verifier is requesting access to your credential',
                      style: TextStyle(
                          fontSize: 12, color: Colors.indigo.shade600),
                      textAlign: TextAlign.center,
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),

            // ── What credential is being requested ───────────────
            Card(
              elevation: 2,
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(16)),
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(children: [
                      Icon(Icons.badge_outlined,
                          color: Colors.green.shade700, size: 20),
                      const SizedBox(width: 8),
                      Text('Credential Requested',
                          style: TextStyle(
                              fontSize: 14,
                              fontWeight: FontWeight.bold,
                              color: Colors.green.shade800)),
                    ]),
                    const Divider(height: 20),
                    _infoRow('Type', _credentialLabel(widget.ref)),
                    const SizedBox(height: 8),
                    _infoRow('Credential ref', widget.ref),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 12),

            // ── Session details ──────────────────────────────────
            Card(
              elevation: 2,
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(16)),
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(children: [
                      Icon(Icons.receipt_long_outlined,
                          color: Colors.teal.shade700, size: 20),
                      const SizedBox(width: 8),
                      Text('Session Details',
                          style: TextStyle(
                              fontSize: 14,
                              fontWeight: FontWeight.bold,
                              color: Colors.teal.shade800)),
                    ]),
                    const Divider(height: 20),
                    _infoRow('openacTransactionId', widget.openacTransactionId),
                    const SizedBox(height: 8),
                    _infoRow('walletTxId', widget.walletTxId),
                  ],
                ),
              ),
            ),

            // ── Error ────────────────────────────────────────────
            if (_error != null) ...[
              const SizedBox(height: 12),
              Card(
                color: Colors.red.shade50,
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12)),
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Text('Error: $_error',
                      style: TextStyle(
                          color: Colors.red.shade800, fontSize: 13)),
                ),
              ),
            ],

            const Spacer(),

            // ── Actions ──────────────────────────────────────────
            if (_authUri != null)
              ElevatedButton.icon(
                onPressed: _launching ? null : _openInWallet,
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.indigo,
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.all(16),
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12)),
                ),
                icon: _launching
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(
                            strokeWidth: 2,
                            valueColor: AlwaysStoppedAnimation<Color>(
                                Colors.white)),
                      )
                    : const Icon(Icons.verified_user_outlined),
                label: Text(
                  _launching ? '開啟中…' : 'Verify with Digital Wallet',
                  style: const TextStyle(
                      fontSize: 16, fontWeight: FontWeight.bold),
                ),
              ),
            if (_authUri == null && _error != null) ...[
              ElevatedButton.icon(
                onPressed: _fetchAuthRequest,
                style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.orange,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.all(14),
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(12))),
                icon: const Icon(Icons.refresh),
                label: const Text('Retry'),
              ),
            ],
            const SizedBox(height: 10),
            OutlinedButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Cancel'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _infoRow(String label, String value) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label,
            style: const TextStyle(
                fontWeight: FontWeight.w600, fontSize: 12)),
        const SizedBox(height: 3),
        SelectableText(
          value,
          style: TextStyle(
              fontFamily: 'monospace',
              fontSize: 11,
              color: Colors.grey.shade700),
        ),
      ],
    );
  }
}

// ── OpenCred Verifier → ZK Proof Screen ─────────────────────────────────────
//
// Flow:
//   1. GET <poll_url>          → record current head ID (baseline)
//   2. launchUrl walletDeeplink → wallet fetches auth-request, posts VP to verifier
//   3. Poll <poll_url>?since=N → detect new POST whose body contains vp_token
//   4. Decode VP JWT → vp.verifiableCredential[0] → base JWT (before first ~)
//   5. generatePrepareInput(jwt, issuerPubkeyX, issuerPubkeyY) → write prepare_input.json
//   6. Navigate back to main screen for the full proof pipeline

class _OpenCredProofScreen extends StatefulWidget {
  final String walletDeeplink; // modadigitalwallet://authorize?client_id=...&request_uri=...
  final String requestUri;     // https://...workers.dev/twdiw-uat

  const _OpenCredProofScreen({
    required this.walletDeeplink,
    required this.requestUri,
  });

  @override
  State<_OpenCredProofScreen> createState() => _OpenCredProofScreenState();
}

enum _OcStep { init, ready, polling, extracting, preparing, done, error }

class _OpenCredProofScreenState extends State<_OpenCredProofScreen> {
  _OcStep _step = _OcStep.init;
  int _baselineId = 0;
  String? _vcJwt;
  String? _prepareStatus;
  String? _prepareError;
  String? _error;
  bool _disposed = false;

  String get _pollUrl {
    final uri = Uri.parse(widget.requestUri);
    return uri.replace(path: '/poll').toString();
  }

  @override
  void initState() {
    super.initState();
    _fetchBaseline();
  }

  @override
  void dispose() {
    _disposed = true;
    super.dispose();
  }

  // ── Step 1: get current head so we only look at NEW entries ──────────────

  Future<void> _fetchBaseline() async {
    _setStep(_OcStep.init);
    try {
      final res = await http.get(Uri.parse(_pollUrl));
      if (res.statusCode != 200) throw Exception('HTTP ${res.statusCode} from poll endpoint');
      final body = jsonDecode(res.body) as Map<String, dynamic>;
      final head = (body['head'] as num?)?.toInt() ?? 0;
      if (!_disposed) setState(() { _baselineId = head; _step = _OcStep.ready; });
    } catch (e) {
      _setError(e.toString());
    }
  }

  // ── Step 2 + 3: launch wallet then poll until VP arrives ─────────────────

  Future<void> _launchAndPoll() async {
    try {
      // Use the same launch path as _QrConfirmScreen (proven to open the wallet app).
      // _launchInWallet decodes the URI and appends openac_callback; the wallet still
      // posts the VP to response_uri, which we collect via polling.
      await launchUrl(
        Uri.parse(_kModaVpQrUrl),
        mode: LaunchMode.externalApplication,
      );
    } catch (e) {
      _setError('Failed to open wallet app: $e');
      return;
    }
    _setStep(_OcStep.polling);
    await _pollForVp();
  }

  Future<void> _pollForVp() async {
    int sinceId = _baselineId;
    const pollInterval = Duration(seconds: 2);
    const maxAttempts = 90; // 3 minutes

    for (int i = 0; i < maxAttempts && !_disposed; i++) {
      await Future.delayed(pollInterval);
      try {
        final res = await http.get(Uri.parse('$_pollUrl?since=$sinceId'));
        if (res.statusCode != 200) continue;
        final data = jsonDecode(res.body) as Map<String, dynamic>;
        final entries = (data['entries'] as List?) ?? [];
        for (final e in entries) {
          final id = (e['id'] as num?)?.toInt() ?? 0;
          if (id > sinceId) sinceId = id;
          final entryBody = e['data']?['body'] as String? ?? '';
          if (entryBody.contains('vp_token')) {
            final params = Uri.splitQueryString(entryBody);
            final vpToken = params['vp_token'];
            if (vpToken != null && vpToken.isNotEmpty) {
              await _extractAndPrepare(vpToken);
              return;
            }
          }
        }
      } catch (_) {
        // transient network error; keep polling
      }
    }
    if (!_disposed) _setError('Timed out waiting for VP from wallet (3 min)');
  }

  // ── Step 4 + 5: extract VC, run generatePrepareInput ────────────────────

  Future<void> _extractAndPrepare(String vpToken) async {
    _setStep(_OcStep.extracting);
    try {
      // Extract VP JWT signing input (header.payload) and device signature for show proof.
      final vpParts = vpToken.split('.');
      if (vpParts.length >= 3) {
        _pendingVpSigningInput = '${vpParts[0]}.${vpParts[1]}';
        // sig may be followed by ~disclosures~; strip those.
        _pendingVpDeviceSig = vpParts[2].split('~')[0];
        debugPrint('[VP] signing input length=${_pendingVpSigningInput!.length}  sig=${_pendingVpDeviceSig!.substring(0, 16)}…');
      }

      final vc = _extractVcJwt(vpToken);
      if (vc == null) throw Exception('No verifiableCredential found in VP token');

      final signingLen = '${vc.split('.')[0]}.${vc.split('.')[1]}'.length;
      if (signingLen > 2048) {
        throw Exception(
          'VC signing input is $signingLen bytes — exceeds circuit MAX_MSG_LEN=2048.\n'
          'This credential type is too large for the current 2k circuit.',
        );
      }

      if (!_disposed) setState(() { _vcJwt = vc; _step = _OcStep.preparing; });

      final dir = await getApplicationDocumentsDirectory();
      final docs = dir.path;
      final jsonStr = await generatePrepareInput(
        jwt: vc,
        issuerPubkeyX: _kIssuerPubkeyX,
        issuerPubkeyY: _kIssuerPubkeyY,
      );
      await File('$docs/jwt_input.json').writeAsString(jsonStr);
      final parsed = jsonDecode(jsonStr) as Map<String, dynamic>;

      if (!_disposed) {
        setState(() {
          _prepareStatus =
              'messageLength=${parsed['messageLength']}  '
              'periodIndex=${parsed['periodIndex']}  '
              'matchesCount=${parsed['matchesCount']}';
          _step = _OcStep.done;
        });
      }
    } catch (e) {
      final msg = await _zkErrorMessage(e);
      if (!_disposed) setState(() { _prepareError = msg; _step = _OcStep.error; });
    }
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  // Decodes a VP JWT and returns the base JWT from the first verifiableCredential
  // (the part before the first ~ in the sd-jwt).
  String? _extractVcJwt(String vpToken) {
    try {
      final parts = vpToken.split('.');
      if (parts.length < 2) return null;
      final payload = parts[1];
      final padded = payload.padRight(payload.length + (4 - payload.length % 4) % 4, '=');
      final raw = base64.decode(padded.replaceAll('-', '+').replaceAll('_', '/'));
      final decoded = utf8.decode(raw);
      final json = jsonDecode(decoded) as Map<String, dynamic>;
      final vcs = json['vp']?['verifiableCredential'] as List?;
      if (vcs == null || vcs.isEmpty) return null;
      final sdJwt = vcs[0] as String;
      return sdJwt.split('~').first; // strip disclosures / KB-JWT
    } catch (_) {
      return null;
    }
  }

  void _setStep(_OcStep s) { if (!_disposed) setState(() { _step = s; _error = null; }); }
  void _setError(String e) { if (!_disposed) setState(() { _step = _OcStep.error; _error = e; }); }

  // ── UI ───────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('OpenCred → ZK Proof')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            _buildConnectionCard(),
            const SizedBox(height: 12),
            _buildPresentationCard(),
            const SizedBox(height: 12),
            _buildProofCard(),
            const SizedBox(height: 20),
            ..._buildActions(),
          ],
        ),
      ),
    );
  }

  Widget _buildConnectionCard() {
    final connected = _step != _OcStep.init && _step != _OcStep.error;
    return _stepCard(
      step: 1,
      title: 'Verifier Connection',
      icon: Icons.cloud_outlined,
      color: Colors.blue,
      done: connected,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _mono('request_uri', widget.requestUri),
          const SizedBox(height: 6),
          _mono('poll endpoint', _pollUrl),
          if (_step == _OcStep.init) ...[
            const SizedBox(height: 8),
            const Row(children: [
              SizedBox(width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2)),
              SizedBox(width: 8),
              Text('Connecting to verifier…', style: TextStyle(fontSize: 12)),
            ]),
          ],
          if (connected) ...[
            const SizedBox(height: 6),
            Row(children: [
              Icon(Icons.check_circle, color: Colors.green.shade600, size: 14),
              const SizedBox(width: 4),
              Text('Baseline log ID: $_baselineId',
                  style: TextStyle(fontSize: 11, color: Colors.green.shade700)),
            ]),
          ],
        ],
      ),
    );
  }

  Widget _buildPresentationCard() {
    final done = _step == _OcStep.extracting ||
        _step == _OcStep.preparing ||
        _step == _OcStep.done ||
        (_step == _OcStep.error && _prepareError != null);
    final polling = _step == _OcStep.polling;
    return _stepCard(
      step: 2,
      title: 'Wallet Presentation',
      icon: Icons.phone_android,
      color: Colors.teal,
      done: done,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (_step == _OcStep.ready || _step == _OcStep.polling) ...[
            Text(
              'The wallet will present your credential to the verifier.\n'
              'After presenting, the app polls for the VP token.',
              style: TextStyle(fontSize: 12, color: Colors.grey.shade700),
            ),
          ],
          if (polling) ...[
            const SizedBox(height: 10),
            Row(children: [
              const SizedBox(width: 14, height: 14,
                  child: CircularProgressIndicator(strokeWidth: 2)),
              const SizedBox(width: 8),
              Text('Waiting for wallet to present credential…',
                  style: TextStyle(fontSize: 12, color: Colors.teal.shade700)),
            ]),
          ],
          if (done) ...[
            const SizedBox(height: 6),
            Row(children: [
              Icon(Icons.check_circle, color: Colors.green.shade600, size: 14),
              const SizedBox(width: 4),
              const Text('VP token received', style: TextStyle(fontSize: 11)),
            ]),
            if (_vcJwt != null) ...[
              const SizedBox(height: 4),
              Text(
                'VC signing input: ${_vcJwt!.split('.')[0].length + 1 + _vcJwt!.split('.')[1].length} bytes',
                style: TextStyle(fontSize: 11, color: Colors.grey.shade600),
              ),
            ],
          ],
        ],
      ),
    );
  }

  Widget _buildProofCard() {
    return _stepCard(
      step: 3,
      title: 'Generate Prepare Input',
      icon: Icons.input,
      color: Colors.cyan.shade700,
      done: _step == _OcStep.done,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (_step == _OcStep.preparing) ...[
            const Row(children: [
              SizedBox(width: 14, height: 14,
                  child: CircularProgressIndicator(strokeWidth: 2)),
              SizedBox(width: 8),
              Text('Running generatePrepareInput…', style: TextStyle(fontSize: 12)),
            ]),
          ],
          if (_step == _OcStep.done && _prepareStatus != null) ...[
            Row(children: [
              Icon(Icons.check_circle, color: Colors.green.shade600, size: 14),
              const SizedBox(width: 4),
              Expanded(
                child: Text(_prepareStatus!,
                    style: TextStyle(fontSize: 11, color: Colors.green.shade700,
                        fontFamily: 'monospace')),
              ),
            ]),
            const SizedBox(height: 8),
            Text(
              'prepare_input.json written. Use the main screen to run the full\n'
              'proof pipeline (Setup → Blinds → Prove JWT → Reblind → Verify).',
              style: TextStyle(fontSize: 11, color: Colors.grey.shade600),
            ),
          ],
          if (_step == _OcStep.error && _prepareError != null) ...[
            Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Icon(Icons.error, color: Colors.red.shade600, size: 14),
              const SizedBox(width: 4),
              Expanded(
                child: Text(_prepareError!,
                    style: TextStyle(fontSize: 11, color: Colors.red.shade700)),
              ),
            ]),
          ],
        ],
      ),
    );
  }

  List<Widget> _buildActions() {
    final actions = <Widget>[];

    if (_step == _OcStep.ready) {
      actions.add(ElevatedButton.icon(
        onPressed: _launchAndPoll,
        icon: const Icon(Icons.verified_user_outlined),
        label: const Text('Launch Wallet & Prove'),
        style: ElevatedButton.styleFrom(
          backgroundColor: Colors.indigo,
          foregroundColor: Colors.white,
          padding: const EdgeInsets.all(16),
        ),
      ));
    }

    if (_step == _OcStep.error && _prepareError == null) {
      // Connection/extraction error → retry from baseline
      actions.add(ElevatedButton.icon(
        onPressed: _fetchBaseline,
        icon: const Icon(Icons.refresh),
        label: const Text('Retry'),
        style: ElevatedButton.styleFrom(
          backgroundColor: Colors.orange,
          foregroundColor: Colors.white,
          padding: const EdgeInsets.all(14),
        ),
      ));
    }

    if (_step == _OcStep.done) {
      actions.add(ElevatedButton.icon(
        onPressed: () => Navigator.of(context).popUntil((r) => r.isFirst),
        icon: const Icon(Icons.play_circle_filled),
        label: const Text('Go to Proof Pipeline'),
        style: ElevatedButton.styleFrom(
          backgroundColor: Colors.indigo,
          foregroundColor: Colors.white,
          padding: const EdgeInsets.all(16),
        ),
      ));
    }

    if (_error != null) {
      actions.add(Card(
        color: Colors.red.shade50,
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Text('Error: $_error',
              style: TextStyle(color: Colors.red.shade800, fontSize: 13)),
        ),
      ));
    }

    actions.add(const SizedBox(height: 8));
    actions.add(OutlinedButton(
      onPressed: () => Navigator.of(context).pop(),
      child: const Text('Cancel'),
    ));

    return actions;
  }

  // ── Shared UI helpers ────────────────────────────────────────────────────

  Widget _stepCard({
    required int step,
    required String title,
    required IconData icon,
    required Color color,
    required bool done,
    required Widget child,
  }) {
    return Card(
      elevation: 2,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: done
            ? BorderSide(color: color, width: 1.5)
            : BorderSide(color: Colors.grey.shade200),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(children: [
              CircleAvatar(
                radius: 14,
                backgroundColor: done ? color : Colors.grey.shade300,
                child: Text('$step',
                    style: TextStyle(
                      color: done ? Colors.white : Colors.grey.shade600,
                      fontSize: 12, fontWeight: FontWeight.bold,
                    )),
              ),
              const SizedBox(width: 10),
              Icon(icon, color: color, size: 20),
              const SizedBox(width: 8),
              Text(title,
                  style: TextStyle(fontSize: 15, fontWeight: FontWeight.bold,
                      color: Colors.grey.shade800)),
              if (done) ...[
                const Spacer(),
                Icon(Icons.check_circle, color: color, size: 18),
              ],
            ]),
            const SizedBox(height: 12),
            child,
          ],
        ),
      ),
    );
  }

  Widget _mono(String label, String value) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w600)),
        const SizedBox(height: 2),
        SelectableText(value,
            style: TextStyle(fontFamily: 'monospace', fontSize: 10,
                color: Colors.grey.shade700)),
      ],
    );
  }
}
