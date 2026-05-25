import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'package:path_provider/path_provider.dart';

import 'package:mopro_flutter_bindings/src/rust/third_party/openac_mobile_app.dart'
    show
        ProofResult,
        generatePrepareInput,
        generateSharedBlinds,
        proveJwt,
        proveShow,
        reblindJwt,
        reblindShow,
        setupJwtKeys,
        setupShowKeys,
        verifyJwt,
        verifyShow;

const String _kIssuerPubkeyX =
    '53578245562568858090497762971050088637552636662548898700080252253957930675571';
const String _kIssuerPubkeyY =
    '94717717123739987908966931526384127659809793164315839803856846695569747893398';

const _kProofSubmitUrl = 'https://alcohol-purchase-frontend.vivi43222.workers.dev/openac/proof';

/// Displays a parsed vc+sd-jwt credential and runs the full ZK-proof pipeline
/// inline when the user taps "Generate ZK Proof".
class CredentialPage extends StatefulWidget {
  final String sdJwt;
  final String? transactionId;

  const CredentialPage({super.key, required this.sdJwt, this.transactionId});

  @override
  State<CredentialPage> createState() => _CredentialPageState();
}

class _CredentialPageState extends State<CredentialPage> {
  bool _pipelineRunning = false;
  bool _pipelineDone = false;
  String? _pipelineError;
  int _currentStepIndex = 0;
  String _currentSubStep = '';
  final Set<int> _completedSteps = {};

  bool _submitting = false;
  String? _submitResult;
  String? _submitError;

  // Synthetic ECDSA test vectors from circom/inputs/show/2k/default.json.
  // The Show circuit verifies device-key possession (ECDSA over nonce hash)
  // independently from the credential's cnf.jwk. Proving with the real device
  // key requires the Secure Enclave private key (unavailable here), so we use
  // precomputed values that satisfy all circuit constraints.
  static const _kTestShowInput = {
    'deviceKeyX':
        '70867448702559710706831157867104375348666111976485036757500306755907228884591',
    'deviceKeyY':
        '95330439344815577998657911774240551168106261928322957515823793358082361230370',
    'sig_r':
        '97632141132390985819876785886928667193064512393283543898194803008435992732086',
    'sig_s_inverse':
        '106822633150040209395395885354646968871852125874546732758721975965629038861865',
    'messageHash':
        '21526899450503750036093500952609951056866772331291366231662559071055169445756',
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

  static const _kStepNames = [
    'Generate Inputs',
    'Key Setup',
    'Shared Blinds',
    'JWT Proof',
    'Show Proof',
    'Verify Proofs',
  ];

  // ── Pipeline ───────────────────────────────────────────────────────────────

  Future<String> _getDocumentsPath() async {
    final dir = await getApplicationDocumentsDirectory();
    return '${dir.path}/circom';
  }

  Future<void> _runFullPipeline() async {
    setState(() {
      _pipelineRunning = true;
      _pipelineDone = false;
      _pipelineError = null;
      _currentStepIndex = 0;
      _currentSubStep = '';
      _completedSteps.clear();
    });

    try {
      final docs = await _getDocumentsPath();
      final jwtPart = widget.sdJwt.split('~').first;

      // Step 1: Generate Inputs
      setState(() {
        _currentStepIndex = 1;
        _currentSubStep = 'Generate prepare input…';
      });
      final prepareJson = await generatePrepareInput(
        jwt: jwtPart,
        issuerPubkeyX: _kIssuerPubkeyX,
        issuerPubkeyY: _kIssuerPubkeyY,
      );
      await File('$docs/prepare_input.json').writeAsString(prepareJson);
      final prepareData = jsonDecode(prepareJson) as Map<String, dynamic>;
      final claimValues =
          (prepareData['claimValues'] as List?)?.map((e) => e.toString()).toList() ??
              ['0', '0'];

      setState(() => _currentSubStep = 'Generate show input…');
      final showInput = Map<String, dynamic>.from(_kTestShowInput);
      showInput['claimValues'] = claimValues;
      await File('$docs/show_input.json').writeAsString(jsonEncode(showInput));
      setState(() => _completedSteps.add(1));

      // Step 2: Key Setup
      setState(() {
        _currentStepIndex = 2;
        _currentSubStep = 'Setup JWT keys…';
      });
      await setupJwtKeys(documentsPath: docs);
      setState(() => _currentSubStep = 'Setup show keys…');
      await setupShowKeys(documentsPath: docs);
      setState(() => _completedSteps.add(2));

      // Step 3: Shared Blinds
      setState(() {
        _currentStepIndex = 3;
        _currentSubStep = 'Generate shared blinds…';
      });
      await generateSharedBlinds(documentsPath: docs);
      setState(() => _completedSteps.add(3));

      // Step 4: JWT Proof
      setState(() {
        _currentStepIndex = 4;
        _currentSubStep = 'Prove JWT…';
      });
      final ProofResult jwtProofResult = await proveJwt(documentsPath: docs);
      setState(() => _currentSubStep = 'Reblind JWT…');
      final ProofResult jwtReblindResult = await reblindJwt(documentsPath: docs);
      setState(() => _completedSteps.add(4));

      // Step 5: Show Proof
      setState(() {
        _currentStepIndex = 5;
        _currentSubStep = 'Prove show…';
      });
      final ProofResult showProofResult = await proveShow(documentsPath: docs);
      setState(() => _currentSubStep = 'Reblind show…');
      final ProofResult showReblindResult = await reblindShow(documentsPath: docs);
      setState(() => _completedSteps.add(5));

      // Step 6: Verify Proofs
      setState(() {
        _currentStepIndex = 6;
        _currentSubStep = 'Verify JWT…';
      });
      final jwtOk = await verifyJwt(documentsPath: docs);
      if (!jwtOk) throw Exception('JWT verification failed');
      setState(() => _currentSubStep = 'Verify show…');
      final showOk = await verifyShow(documentsPath: docs);
      if (!showOk) throw Exception('Show verification failed');
      setState(() => _completedSteps.add(6));

      setState(() {
        _pipelineRunning = false;
        _pipelineDone = true;
      });
    } catch (e) {
      setState(() {
        _pipelineRunning = false;
        _pipelineError = e.toString();
      });
    }
  }

  // ── Submit proof ───────────────────────────────────────────────────────────

  Future<void> _submitProof() async {
    setState(() {
      _submitting = true;
      _submitResult = null;
      _submitError = null;
    });
    try {
      final docs = await _getDocumentsPath();
      final prepareBytes =
          await File('$docs/keys/prepare_proof.bin').readAsBytes();
      final showBytes = await File('$docs/keys/show_proof.bin').readAsBytes();

      final body = jsonEncode({
        'transactionId': widget.transactionId ?? '',
        'prepareProof': base64Encode(prepareBytes),
        'showProof': base64Encode(showBytes),
      });

      final res = await http.post(
        Uri.parse(_kProofSubmitUrl),
        headers: {'Content-Type': 'application/json'},
        body: body,
      );

      if (!mounted) return;
      if (res.statusCode >= 200 && res.statusCode < 300) {
        setState(() {
          _submitting = false;
          _submitResult = res.body;
        });
      } else {
        throw Exception('HTTP ${res.statusCode}: ${res.body}');
      }
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _submitting = false;
        _submitError = e.toString();
      });
    }
  }

  // ── Parsing helpers ────────────────────────────────────────────────────────

  static String _b64urlDecode(String s) {
    final norm = s.replaceAll('-', '+').replaceAll('_', '/');
    final padded = norm.padRight((norm.length + 3) ~/ 4 * 4, '=');
    return utf8.decode(base64.decode(padded));
  }

  Map<String, dynamic> _payload() {
    try {
      final jwt = widget.sdJwt.split('~').first;
      final parts = jwt.split('.');
      if (parts.length < 2) return {};
      return jsonDecode(_b64urlDecode(parts[1])) as Map<String, dynamic>;
    } catch (_) {
      return {};
    }
  }

  List<MapEntry<String, String>> _disclosures() {
    final result = <MapEntry<String, String>>[];
    final parts = widget.sdJwt.split('~');
    for (int i = 1; i < parts.length; i++) {
      final d = parts[i];
      if (d.isEmpty) continue;
      try {
        final arr = jsonDecode(_b64urlDecode(d)) as List;
        if (arr.length >= 3) {
          result.add(MapEntry(arr[1].toString(), arr[2].toString()));
        }
      } catch (_) {}
    }
    return result;
  }

  static String _fmtEpoch(dynamic epochSec) {
    if (epochSec == null) return '—';
    try {
      final dt = DateTime.fromMillisecondsSinceEpoch(
          (epochSec as num).toInt() * 1000,
          isUtc: true);
      return '${dt.year}-${dt.month.toString().padLeft(2, '0')}-${dt.day.toString().padLeft(2, '0')}';
    } catch (_) {
      return epochSec.toString();
    }
  }

  static String _truncate(String? s, {int head = 18, int tail = 8}) {
    if (s == null) return '—';
    if (s.length <= head + tail + 3) return s;
    return '${s.substring(0, head)}…${s.substring(s.length - tail)}';
  }

  // ── Build ──────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    final p = _payload();
    final disclosures = _disclosures();
    final jwk = (p['cnf']?['jwk'] as Map?)?.cast<String, dynamic>() ?? {};
    final vcTypes = ((p['vc']?['type']) as List?)?.cast<String>() ?? [];
    final credType =
        vcTypes.where((t) => t != 'VerifiableCredential').join(', ');
    final status =
        (p['vc']?['credentialStatus'] as Map?)?.cast<String, dynamic>() ?? {};

    return Scaffold(
      appBar: AppBar(
        title: const Text('Credential Detail'),
        actions: [
          IconButton(
            icon: const Icon(Icons.copy),
            tooltip: 'Copy SD-JWT',
            onPressed: () {
              Clipboard.setData(ClipboardData(text: widget.sdJwt));
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                  content: Text('SD-JWT copied to clipboard'),
                  duration: Duration(seconds: 2),
                ),
              );
            },
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _TypeBadge(
              label: credType.isEmpty ? 'Verifiable Credential' : credType),
          const SizedBox(height: 16),

          _InfoCard(
            title: 'Identity',
            icon: Icons.person_outline,
            color: Colors.blue,
            rows: [
              _InfoRow('Issuer', _truncate(p['iss']?.toString())),
              _InfoRow('Subject', _truncate(p['sub']?.toString())),
              _InfoRow('Valid From', _fmtEpoch(p['nbf'])),
              _InfoRow('Expires', _fmtEpoch(p['exp'])),
              if (p['nonce'] != null) _InfoRow('Nonce', p['nonce'].toString()),
            ],
          ),
          const SizedBox(height: 12),

          if (disclosures.isNotEmpty) ...[
            _InfoCard(
              title: 'Disclosed Claims',
              icon: Icons.list_alt,
              color: Colors.orange,
              rows: disclosures.map((e) => _InfoRow(e.key, e.value)).toList(),
            ),
            const SizedBox(height: 12),
          ],

          if (jwk.isNotEmpty) ...[
            _InfoCard(
              title: 'Device Key (cnf.jwk)',
              icon: Icons.phonelink_lock,
              color: Colors.deepPurple,
              rows: [
                _InfoRow(
                    'Key Type', '${jwk['kty'] ?? '—'} / ${jwk['crv'] ?? '—'}'),
                _InfoRow(
                    'x', _truncate(jwk['x']?.toString(), head: 20, tail: 6)),
                _InfoRow(
                    'y', _truncate(jwk['y']?.toString(), head: 20, tail: 6)),
              ],
            ),
            const SizedBox(height: 12),
          ],

          if (status.isNotEmpty) ...[
            _InfoCard(
              title: 'Credential Status',
              icon: Icons.info_outline,
              color: Colors.teal,
              rows: [
                _InfoRow('Type', status['type']?.toString() ?? '—'),
                _InfoRow(
                    'List Index', status['statusListIndex']?.toString() ?? '—'),
                _InfoRow(
                    'Purpose', status['statusPurpose']?.toString() ?? '—'),
              ],
            ),
            const SizedBox(height: 12),
          ],

          if (_pipelineRunning || _pipelineDone || _pipelineError != null) ...[
            _buildPipelineCard(),
            const SizedBox(height: 12),
          ],

          if (_submitError != null)
            Card(
              color: Colors.red.shade50,
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12)),
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Row(
                  children: [
                    Icon(Icons.error_outline,
                        color: Colors.red.shade700, size: 18),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text('Submit error: $_submitError',
                          style: TextStyle(
                              color: Colors.red.shade800, fontSize: 13)),
                    ),
                  ],
                ),
              ),
            ),

          if (_submitResult != null)
            Card(
              color: Colors.green.shade50,
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12)),
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(children: [
                      Icon(Icons.check_circle,
                          color: Colors.green.shade700, size: 18),
                      const SizedBox(width: 8),
                      Text('Proof submitted',
                          style: TextStyle(
                              fontWeight: FontWeight.bold,
                              color: Colors.green.shade800)),
                    ]),
                    const SizedBox(height: 8),
                    SelectableText(
                      _submitResult!,
                      style: TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 11,
                          color: Colors.green.shade900),
                    ),
                  ],
                ),
              ),
            ),

          if (_submitResult != null) const SizedBox(height: 12),
          if (_submitError != null) const SizedBox(height: 12),

          if (!_pipelineDone)
            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                onPressed: _pipelineRunning ? null : _runFullPipeline,
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.indigo,
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(vertical: 16),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
                icon: _pipelineRunning
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(
                            strokeWidth: 2, color: Colors.white),
                      )
                    : const Icon(Icons.play_circle_filled),
                label: Text(
                  _pipelineRunning ? 'Running…' : 'Generate ZK Proof',
                  style: const TextStyle(
                      fontSize: 16, fontWeight: FontWeight.bold),
                ),
              ),
            ),

          if (_pipelineDone)
            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                onPressed: _submitting ? null : _submitProof,
                style: ElevatedButton.styleFrom(
                  backgroundColor: _submitResult != null
                      ? Colors.green.shade700
                      : Colors.teal.shade700,
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(vertical: 16),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
                icon: _submitting
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(
                            strokeWidth: 2, color: Colors.white),
                      )
                    : Icon(_submitResult != null
                        ? Icons.check_circle
                        : Icons.upload_outlined),
                label: Text(
                  _submitting
                      ? 'Submitting…'
                      : _submitResult != null
                          ? 'Proof Submitted'
                          : 'Submit Proof',
                  style: const TextStyle(
                      fontSize: 16, fontWeight: FontWeight.bold),
                ),
              ),
            ),

          const SizedBox(height: 16),
        ],
      ),
    );
  }

  Widget _buildPipelineCard() {
    return Card(
      elevation: 2,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(children: [
              if (_pipelineRunning)
                const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              else if (_pipelineDone)
                const Icon(Icons.check_circle, color: Colors.green, size: 18)
              else
                const Icon(Icons.error, color: Colors.red, size: 18),
              const SizedBox(width: 8),
              Text(
                _pipelineDone
                    ? 'Proof Generated'
                    : _pipelineError != null
                        ? 'Failed'
                        : 'Generating Proof…',
                style: const TextStyle(
                    fontWeight: FontWeight.bold, fontSize: 15),
              ),
            ]),
            const SizedBox(height: 12),
            const Divider(height: 1),
            const SizedBox(height: 10),
            ...List.generate(_kStepNames.length, (i) {
              final stepNum = i + 1;
              final isDone = _completedSteps.contains(stepNum);
              final isRunning =
                  _pipelineRunning && _currentStepIndex == stepNum;
              final isFailed =
                  _pipelineError != null && _currentStepIndex == stepNum;

              return Padding(
                padding: const EdgeInsets.symmetric(vertical: 5),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    SizedBox(
                      width: 20,
                      height: 20,
                      child: isDone
                          ? const Icon(Icons.check_circle,
                              color: Colors.green, size: 18)
                          : isRunning
                              ? const CircularProgressIndicator(strokeWidth: 2)
                              : isFailed
                                  ? const Icon(Icons.error,
                                      color: Colors.red, size: 18)
                                  : Icon(Icons.circle_outlined,
                                      color: Colors.grey.shade400, size: 18),
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'Step $stepNum: ${_kStepNames[i]}',
                            style: TextStyle(
                              fontSize: 13,
                              fontWeight: isRunning
                                  ? FontWeight.bold
                                  : FontWeight.normal,
                              color: isDone
                                  ? Colors.green.shade700
                                  : isFailed
                                      ? Colors.red.shade700
                                      : isRunning
                                          ? Colors.black87
                                          : Colors.grey.shade400,
                            ),
                          ),
                          if (isRunning && _currentSubStep.isNotEmpty)
                            Padding(
                              padding: const EdgeInsets.only(top: 2),
                              child: Text(
                                _currentSubStep,
                                style: TextStyle(
                                    fontSize: 11,
                                    color: Colors.grey.shade600),
                              ),
                            ),
                          if (isFailed && _pipelineError != null)
                            Padding(
                              padding: const EdgeInsets.only(top: 2),
                              child: Text(
                                _pipelineError!,
                                style: TextStyle(
                                    fontSize: 11,
                                    color: Colors.red.shade700),
                              ),
                            ),
                        ],
                      ),
                    ),
                  ],
                ),
              );
            }),
          ],
        ),
      ),
    );
  }
}

// ── Sub-widgets ───────────────────────────────────────────────────────────────

class _TypeBadge extends StatelessWidget {
  final String label;
  const _TypeBadge({required this.label});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: Colors.green.shade50,
        border: Border.all(color: Colors.green.shade300),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Row(
        children: [
          Icon(Icons.verified, color: Colors.green.shade700, size: 20),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              label,
              style: TextStyle(
                fontWeight: FontWeight.bold,
                color: Colors.green.shade800,
                fontSize: 15,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _InfoCard extends StatelessWidget {
  final String title;
  final IconData icon;
  final Color color;
  final List<_InfoRow> rows;

  const _InfoCard({
    required this.title,
    required this.icon,
    required this.color,
    required this.rows,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      elevation: 2,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(children: [
              Icon(icon, color: color, size: 18),
              const SizedBox(width: 8),
              Text(title,
                  style: const TextStyle(
                      fontWeight: FontWeight.bold, fontSize: 15)),
            ]),
            const SizedBox(height: 10),
            const Divider(height: 1),
            const SizedBox(height: 8),
            ...rows.map((r) => r.build()),
          ],
        ),
      ),
    );
  }
}

class _InfoRow {
  final String label;
  final String value;
  const _InfoRow(this.label, this.value);

  Widget build() {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 5),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 96,
            child: Text(
              label,
              style: TextStyle(
                fontSize: 12,
                color: Colors.grey.shade600,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: const TextStyle(fontSize: 13),
            ),
          ),
        ],
      ),
    );
  }
}
