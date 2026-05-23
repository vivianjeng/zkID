import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show rootBundle;
import 'package:path_provider/path_provider.dart';

import 'package:mopro_flutter_bindings/src/rust/frb_generated.dart';
import 'package:mopro_flutter_bindings/src/rust/third_party/openac_mobile_app.dart'
    show
        BenchmarkResults,
        ProofResult,
        generatePrepareInput,
        generateSharedBlinds,
        proveJwt,
        proveShow,
        reblindJwt,
        reblindShow,
        runCompleteBenchmark,
        setupJwtKeys,
        setupShowKeys,
        verifyJwt,
        verifyShow;

// Real vc+sd-jwt credential — Taiwan government wallet demo, alg ES256, no disclosures.
// Issuer public key "key-1" coordinates (decimal); verified against the live JWK Set.
const String _kIssuerPubkeyX =
    '53578245562568858090497762971050088637552636662548898700080252253957930675571';
const String _kIssuerPubkeyY =
    '94717717123739987908966931526384127659809793164315839803856846695569747893398';
const String _kCredentialJwt =
    'eyJqa3UiOiJodHRwczovL2lzc3Vlci12Yy53YWxsZXQuZ292LnR3L2FwaS9rZXlzIiwia2lkIjoia2V5LTEiLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9'
    '.eyJzdWIiOiJkaWQ6a2V5OnoyZG16RDgxZDI0b3g3cVp4NmJ2TndENzNja2lXZkRCQzV5NHpnckNMdVRuMXBNQnpGWFBIdHVXUDEyY1lQRmRSdjQ5MlE4WDFYZVoyeVg3U1pZWDloV1RaV0F2QXpUWFMydkJIakI2QnhxOGZGeEd5ZTRTd1dtcWdaODZRU3lkd2hoRHU5eTZLV2dlZDlhVkFlTFpjbUNXTHFzZ21CVUJDaG50SGdvSHhtczVadXZDTFUiLCJuYmYiOjE3Nzg1MTUyMDAsImlzcyI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticlRRV1BUSk10MkZ1MTZIODR5bXdiYkc5TEdOaW5XN1luajUzWkNBVzE2Z3JBaEJpd3Y1M0FuYnY3ODdodDZueGFLTUdHQWdZOVdqdEZ4WVozaGpHZE1kMVNodVFvU3ZOZVh4Y2o1SmNiazJ1WXRmR2J3aW9GU2laUVhmekg3Y3RoaSIsImNuZiI6eyJqd2siOnsieSI6Ilpza1oyQ2dmWWpDZWpDaUFNdzNnZ3JReHZ2TlJNLUpOTEtWU0xEcjNjdWsiLCJ4IjoiVkZCd1k3cFg3ZEI0RDF5YXNwYVRIM0luTElLeURCUUU5OFRSVzNISGRmbyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYifX0sImV4cCI6MTc3OTIwNjM5OSwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIjAwMDAwMDAwX2RlbW8iXSwiY3JlZGVudGlhbFN0YXR1cyI6eyJ0eXBlIjoiU3RhdHVzTGlzdDIwMjFFbnRyeSIsImlkIjoiaHR0cHM6Ly9pc3N1ZXItdmMud2FsbGV0Lmdvdi50dy9hcGkvc3RhdHVzLWxpc3QvMDAwMDAwMDBfZGVtby9yMCMxOCIsInN0YXR1c0xpc3RJbmRleCI6IjE4Iiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwczovL2lzc3Vlci12Yy53YWxsZXQuZ292LnR3L2FwaS9zdGF0dXMtbGlzdC8wMDAwMDAwMF9kZW1vL3IwIiwic3RhdHVzUHVycG9zZSI6InJldm9jYXRpb24ifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vZnJvbnRlbmQud2FsbGV0Lmdvdi50dy9hcGkvc2NoZW1hLzAwMDAwMDAwL2RlbW8vVjEvZjFlYTllMTQtNzdhNy00MzRlLWI3MDEtZjhkYjViMGMzMDJkIiwidHlwZSI6Ikpzb25TY2hlbWEifSwiY3JlZGVudGlhbFN1YmplY3QiOnsiX3NkIjpbIjdqcnJDdFlsamJYQ3ZvckpZUXlyNnNZVDVVTzBoYW9ZT1BnUGtGc0U4WkkiXSwiX3NkX2FsZyI6InNoYS0yNTYifX0sIm5vbmNlIjoiR1c4N1dZOTAiLCJqdGkiOiJodHRwczovL2lzc3Vlci12Yy53YWxsZXQuZ292LnR3L2FwaS9jcmVkZW50aWFsLzExMzdkN2RmLTU3YzgtNDU3NS05NjViLTgxZjNkOTE4NTg4OSJ9'
    '.uaSHN7nXORtfcU9PjSaDPdEZ7kqvFbz5sZsqjT2iIFCMPVwgSp8OcoqUSYqu2_TLpYVEk3niIGHp5aZoBwmGHw';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  await _copyAssetsToDocuments();
  runApp(const MyApp());
}

/// Copy circuit files from Flutter assets into the app's documents directory,
/// mirroring the layout used by Rust's PathConfig::mobile:
///
///   {docs}/build/jwt/jwt_js/jwt.r1cs   ← decompressed from jwt.r1cs.gz
///   {docs}/build/show/show_js/show.r1cs ← decompressed from show.r1cs.gz
///   {docs}/jwt_input.json               ← prove_jwt + run_complete_benchmark
///   {docs}/show_input.json              ← prove_show + run_complete_benchmark
Future<void> _copyAssetsToDocuments() async {
  try {
    final documentsDir = await getApplicationDocumentsDirectory();
    final circomDir = Directory('${documentsDir.path}/circom');

    final jwtBuildDir = Directory('${circomDir.path}/build/jwt/jwt_js');
    final showBuildDir = Directory('${circomDir.path}/build/show/show_js');
    await jwtBuildDir.create(recursive: true);
    await showBuildDir.create(recursive: true);

    // Decompress r1cs files — skip if already extracted (each is ~350MB).
    final compressedAssets = {
      'assets/circom/jwt.r1cs.gz': '${jwtBuildDir.path}/jwt.r1cs',
      'assets/circom/show.r1cs.gz': '${showBuildDir.path}/show.r1cs',
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
  setupJwt,
  setupShow,
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

  Future<String> _getDocumentsPath() async {
    final dir = await getApplicationDocumentsDirectory();
    return '${dir.path}/circom';
  }

  Future<TaskResult> _executeStep(
      ProofTaskType taskType, String documentsPath) async {
    switch (taskType) {
      case ProofTaskType.setupJwt:
        final t = DateTime.now();
        final msg = await setupJwtKeys(documentsPath: documentsPath);
        return TaskResult(
          taskType: taskType,
          success: true,
          message: msg,
          clientTimingMs: DateTime.now().difference(t).inMilliseconds,
        );

      case ProofTaskType.setupShow:
        final t = DateTime.now();
        final msg = await setupShowKeys(documentsPath: documentsPath);
        return TaskResult(
          taskType: taskType,
          success: true,
          message: msg,
          clientTimingMs: DateTime.now().difference(t).inMilliseconds,
        );

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
      await File('$docs/prepare_input.json').writeAsString(jsonStr);
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

  // Synthetic test vectors from circom/inputs/show/2k/default.json.
  // The Show circuit verifies device-key possession (ECDSA over nonce hash) independently
  // from the JWT's cnf.jwk; a valid proof requires the matching device private key, which
  // is unavailable here. These pre-computed values satisfy all circuit constraints.
  static const _kTestShowInput = {
    'deviceKeyX': '70867448702559710706831157867104375348666111976485036757500306755907228884591',
    'deviceKeyY': '95330439344815577998657911774240551168106261928322957515823793358082361230370',
    'sig_r': '97632141132390985819876785886928667193064512393283543898194803008435992732086',
    'sig_s_inverse': '106822633150040209395395885354646968871852125874546732758721975965629038861865',
    'messageHash': '21526899450503750036093500952609951056866772331291366231662559071055169445756',
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
      final jsonStr = jsonEncode(_kTestShowInput);
      await File('$docs/show_input.json').writeAsString(jsonStr);
      setState(() {
        _showInputStatus =
            'devKeyX=${(_kTestShowInput['deviceKeyX'] as String).substring(0, 8)}…  '
            'msgHash=${(_kTestShowInput['messageHash'] as String).substring(0, 8)}…';
        _generatingShowInput = false;
      });
    } catch (e) {
      setState(() {
        _showInputError = e.toString();
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
      setState(() {
        _results[taskType.name] =
            TaskResult(taskType: taskType, success: false, error: e.toString());
        _completedSteps[taskType.name] = false;
        _error = Exception('${_taskTypeToDisplayName(taskType)} failed: $e');
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
    setState(() => _currentWorkflowStep = '1/11: Generate Prepare Input');
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
    setState(() => _currentWorkflowStep = '2/11: Generate Show Input');
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
      ProofTaskType.setupJwt,
      ProofTaskType.setupShow,
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
            '${i + 3}/11: ${_taskTypeToDisplayName(step)}';
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
        setState(() {
          _results[step.name] =
              TaskResult(taskType: step, success: false, error: e.toString());
          _completedSteps[step.name] = false;
          _error = Exception(
              'Pipeline stopped at ${_taskTypeToDisplayName(step)}: $e');
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
      ProofTaskType.setupJwt => 'Setup JWT',
      ProofTaskType.setupShow => 'Setup Show',
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
  bool get _step2Complete =>
      _completedSteps['setupJwt'] == true &&
      _completedSteps['setupShow'] == true;
  bool get _step3Complete => _completedSteps['generateBlinds'] == true;
  bool get _step4Complete =>
      _completedSteps['proveJwt'] == true &&
      _completedSteps['reblindJwt'] == true;
  bool get _step5Complete =>
      _completedSteps['proveShow'] == true &&
      _completedSteps['reblindShow'] == true;
  bool get _step6Complete =>
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
              title: 'Key Setup',
              icon: Icons.key,
              color: Colors.blue.shade700,
              completed: _step2Complete,
              child: Row(
                children: [
                  Expanded(
                    child: _buildOperationButton(
                      taskType: ProofTaskType.setupJwt,
                      label: 'Setup JWT',
                      icon: Icons.key,
                      color: Colors.blue,
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: _buildOperationButton(
                      taskType: ProofTaskType.setupShow,
                      label: 'Setup Show',
                      icon: Icons.key,
                      color: Colors.blue,
                    ),
                  ),
                ],
              ),
            ),
            _buildConnector(),
            _buildStep(
              step: 3,
              title: 'Generate Shared Blinds',
              icon: Icons.shuffle,
              color: Colors.orange.shade700,
              completed: _step3Complete,
              child: _buildOperationButton(
                taskType: ProofTaskType.generateBlinds,
                label: 'Generate Shared Blinds',
                icon: Icons.shuffle,
                color: Colors.orange,
              ),
            ),
            _buildConnector(),
            _buildStep(
              step: 4,
              title: 'JWT Proof',
              icon: Icons.assignment,
              color: Colors.green.shade700,
              completed: _step4Complete,
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
              step: 5,
              title: 'Show Proof',
              icon: Icons.visibility,
              color: Colors.deepPurple.shade700,
              completed: _step5Complete,
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
              step: 6,
              title: 'Verify Proofs',
              icon: Icons.check_circle,
              color: Colors.teal.shade700,
              completed: _step6Complete,
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
