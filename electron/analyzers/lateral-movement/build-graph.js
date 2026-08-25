/**
 * build-graph.js — the parse->graph->chains spine of the lateral-movement analyzer.
 *
 * The tightly-coupled core, extracted verbatim from getLateralMovement(): the
 * per-row event parser (TerminalServices / 4778-4779 / 4776 / standard Security),
 * graph-edge + host-set building, IP->hostname resolution, RDP session lifecycle
 * correlation (clustering / confidence / reconnect-merge / pre-auth), multi-hop
 * chain detection, first-seen flags, edge technique inference, attack-pattern
 * findings (brute force / spray / credential compromise), and domain naming
 * convention outliers.
 *
 * Mutates the passed edgeMap/hostSet/timeOrdered/rdpEvents/_ipToHostname and the
 * telemetry maps (via the bump helpers) in place, and returns the structures the
 * downstream stage pipeline + result assembly consume.
 *
 * @param {object} state - { rows, columns, meta, options, db, edgeMap, hostSet,
 *   timeOrdered, rdpEvents, _ipToHostname, isEvtxECmd, isHayabusa,
 *   _dedupeEvidenceRefs, _rowEvidenceRef, _refsFromEvents, _rowidsFromRefs,
 *   _bumpHostTelemetry, _bumpUserEvent, _bumpDatasetEvent, _normLmHost,
 *   excludeLocalLogons, excludeServiceAccounts }
 * @returns {{rdpSessions, chains, findings, fid, _outlierHosts, _computerHosts,
 *   _conventionOutliers, detectOutlier}}
 */
const { cleanWrappedField, compactGet, compactGetInt, parseCompactKeyValues, extractFirstInteger, resolveEventChannel } = require("../evtx-utils");
const { detectConventions } = require("./convention-detector");
const { EXCLUDED_IPS, SERVICE_RE, SESSION_ONLY_EVENTS, RDP_CONTEXT_EVENT_IDS, RDP_EVENT_DESC, DC_PAT: _DC_PAT, SRV_PAT: _SRV_PAT } = require("./constants");
const { buildObservedHostAliases, isExcludedEndpoint } = require("./endpoint-normalize");
const { normalizeTimestamp } = require("../../utils/forensic-normalize");

function buildGraphAndChains(state) {
  const {
    rows, columns, meta, options, db, edgeMap, hostSet, timeOrdered, rdpEvents, _ipToHostname,
    isEvtxECmd, isHayabusa, _dedupeEvidenceRefs, _rowEvidenceRef, _refsFromEvents, _rowidsFromRefs,
    _bumpHostTelemetry, _bumpUserEvent, _bumpUserEventScoped, _bumpDatasetEvent, _normLmHost,
    excludeLocalLogons, excludeServiceAccounts, privLogonEvents, hostTelemetry,
  } = state;

      // Single global format (derived from the first/only tab's headers). In multi-source
      // merged mode each row carries its own _sourceFormat and overrides these per-row
      // inside the loop, so a tab whose format differs from the first tab is parsed
      // correctly (previously every merged row was parsed as the first tab's format,
      // silently dropping/mangling usernames and source hosts from the other tabs).
      const _globalIsEvtxECmd = isEvtxECmd;
      const _globalIsHayabusa = isHayabusa;

      for (const row of rows) {
        // Parse each row by ITS OWN source format (set by multi-source.js on merged rows).
        // Without _sourceFormat (single-tab mode) these fall back to the global flags, so
        // single-tab behavior is identical to before. These intentionally shadow the
        // function-scope consts for the duration of the loop body only.
        const isEvtxECmd = row._sourceFormat ? row._sourceFormat === "EvtxECmd" : _globalIsEvtxECmd;
        const isHayabusa = row._sourceFormat ? row._sourceFormat === "Hayabusa" : _globalIsHayabusa;
        let targetHost = _normLmHost(row.target || columns._syntheticTarget || "");
        if (!targetHost || isExcludedEndpoint(targetHost)) continue;

        const eventId = cleanWrappedField(row.eventId || "");
        const evidenceRef = _rowEvidenceRef(row);
        const evidenceRefs = evidenceRef ? [evidenceRef] : [];
        const provenance = evidenceRef ? { evidenceRefs, evidenceRef, tabId: evidenceRef.tabId, rowId: evidenceRef.rowId } : {};

        // Telemetry coverage: count raw events per host BEFORE any filters
        // (coverage reflects what's in the data, not what survived filtering)
        if (eventId) {
          _bumpDatasetEvent(eventId);
          _bumpHostTelemetry(targetHost, eventId);
        }

        // Detect channel for TerminalServices event parsing
        const channelRaw = row._channel ? String(row._channel).toLowerCase() : "";
        const channelNorm = resolveEventChannel(row);
        const isLocalSessionMgr = channelRaw.includes("localsessionmanager") || channelNorm === "localsessionmanager";
        const isRemoteConnMgr = channelRaw.includes("remoteconnectionmanager") || channelNorm === "remoteconnectionmanager";
        const isTermSvc = isLocalSessionMgr || isRemoteConnMgr;

        let clientName = "";
        let clientAddress = "";
        let sourceHost = "";
        let sourceFieldType = ""; // tracks which field resolved sourceHost: "clientName", "workstation", "ip"
        let user = "";
        let logonType = "";
        let sessionId = "";
        let compact = null;

        if (isHayabusa) {
          compact = parseCompactKeyValues(row.details, row.extra);
        }

        // === TerminalServices event parsing ===
        if (isHayabusa) {
          if (eventId === "4648") {
            targetHost = _normLmHost(compactGet(compact, "TgtSvr", "TgtHost")) || targetHost;
          }
          if (eventId === "4778" || eventId === "4779") {
            clientName = compactGet(compact, "SrcComp", "ClientName");
            clientAddress = compactGet(compact, "SrcIP", "ClientAddress");
            sourceHost = _normLmHost(clientName || clientAddress);
            sourceFieldType = clientName ? "clientName" : clientAddress ? "ip" : "";
            user = compactGet(compact, "TgtUser", "TargetUserName", "User");
          } else if (["20","21","22","23","24","25","32","33","34","35","39","40","1149"].includes(eventId)) {
            user = compactGet(compact, "User", "TgtUser", "TargetUserName", "SubjectUserName");
            sourceHost = _normLmHost(compactGet(compact, "SrcComp", "ClientName", "SrcIP", "ClientAddress"));
            sourceFieldType = sourceHost ? "ip" : "";
            logonType = extractFirstInteger(compactGet(compact, "Type", "LogonType"));
            sessionId = compactGetInt(compact, "SessionId", "Session ID", "LID");
          } else {
            sourceHost = _normLmHost(compactGet(compact, "SrcComp", "WorkstationName", "SrcHost"));
            if (sourceHost && sourceHost !== "-") { sourceFieldType = "workstation"; }
            else { sourceHost = _normLmHost(compactGet(compact, "SrcIP", "IpAddress", "SourceNetworkAddress")); sourceFieldType = "ip"; }
            user = compactGet(compact, "TgtUser", "TargetUserName", "SubjectUserName", "User", "SrcUser");
            logonType = extractFirstInteger(compactGet(compact, "Type", "LogonType"));
          }
          if (!targetHost && eventId === "4648") {
            targetHost = _normLmHost(compactGet(compact, "TgtSvr", "TgtHost"));
          }
        } else if (isTermSvc || (!channelRaw && ["20","21","22","23","24","25","32","33","34","35","39","40","1149"].includes(eventId) && isEvtxECmd && row._payloadData3)) {
          const pd1 = (row._payloadData1 || row.user || "").trim();
          const pd2 = (row._payloadData2 || row.logonType || "").trim();
          const pd3 = (row._payloadData3 || "").trim();
          // Raw EVTX has no PayloadData columns, so every regex below misses and the
          // record would be dropped at the !sourceHost guard. The same values arrive as
          // dedicated UserData columns instead — fall back to them, but only after the
          // PayloadData path has had its chance, so EvtxECmd behavior is unchanged.
          const rawSrc = (v) => {
            const s = String(v == null ? "" : v).trim().toUpperCase();
            return (!s || s === "LOCAL" || EXCLUDED_IPS.has(s)) ? "" : s;
          };

          if (isLocalSessionMgr || ["20","21","22","23","24","25","32","33","34","35","39","40"].includes(eventId)) {
            // LocalSessionManager: PD1="User: DOMAIN\user", PD2="Session ID: N", PD3="Source Network Address: x.x.x.x"
            // Guard: EvtxECmd maps PayloadData differently per EID. For EIDs 39/40
            // PD1 is "TargetSession: N" or "Session: N", not "User: ...". The old
            // catch-all regex matched these as usernames, polluting the Accounts tab
            // with entries like "Session ID: 8" or "TargetSession: 9". Reject PD1
            // values that look like session metadata before attempting user extraction.
            const _isSessionMeta = /^(Session(\s*ID)?|TargetSession|Source)\s*:/i.test(pd1);
            const userMatch = _isSessionMeta ? null : pd1.match(/(?:^User:\s*|^)(?:([^\\]+)\\)?(.+)$/i);
            if (userMatch) user = userMatch[2].trim();
            // Also try to extract session ID from PD1 when it's session metadata
            if (_isSessionMeta) {
              const sidFromPd1 = pd1.match(/(?:Session\s*ID|TargetSession|Session)\s*:\s*(\d+)/i);
              if (sidFromPd1) sessionId = sidFromPd1[1];
            }
            const sidMatch = pd2.match(/Session\s*ID:\s*(\d+)/i);
            if (sidMatch) sessionId = sidMatch[1];
            const ipMatch = pd3.match(/Source\s*Network\s*Address:\s*(.+)/i);
            if (ipMatch) {
              const srcIP = ipMatch[1].trim();
              if (srcIP && srcIP !== "LOCAL" && !EXCLUDED_IPS.has(srcIP.toUpperCase())) { sourceHost = srcIP.toUpperCase(); sourceFieldType = "ip"; }
            }
            // Raw EVTX: Address (LSM) — Param3 covers a tab that also holds RCM records.
            if (!sourceHost) {
              const raw = rawSrc(row._rawAddress) || rawSrc(row._rawParam3) || rawSrc(row.source);
              if (raw) { sourceHost = raw; sourceFieldType = "ip"; }
            }
            if (!sessionId) sessionId = extractFirstInteger(row._rawSessionId) || "";
          } else if (isRemoteConnMgr || eventId === "1149") {
            // RemoteConnectionManager 1149: PD1="User: username", PD2="Domain: DOMAIN", PD3="Source Network Address: x.x.x.x"
            const userMatch = pd1.match(/(?:^User:\s*|^)(.+)$/i);
            if (userMatch) user = userMatch[1].trim();
            // Raw EVTX: Param1 is the user. _rawUser covers a tab that also holds LSM
            // records, where columns.user resolved to the LSM `User` column instead.
            if (!user) user = String(row._rawParam1 || row._rawUser || "").trim();
            const ipMatch2 = pd3.match(/Source\s*Network\s*Address:\s*(.+)/i);
            if (ipMatch2) {
              const srcIP = ipMatch2[1].trim();
              if (srcIP && !EXCLUDED_IPS.has(srcIP.toUpperCase())) { sourceHost = srcIP.toUpperCase(); sourceFieldType = "ip"; }
            }
            if (!sourceHost) {
              const raw = rawSrc(row._rawParam3) || rawSrc(row._rawAddress) || rawSrc(row.source);
              if (raw) { sourceHost = raw; sourceFieldType = "ip"; }
            }
            if (!sessionId) sessionId = extractFirstInteger(row._rawSessionId) || "";
          }

        // === 4778/4779: Session reconnect/disconnect — ClientName/ClientAddress ===
        } else if (eventId === "4778" || eventId === "4779") {
          clientName = (row.clientName || "").trim();
          clientAddress = (row.clientAddress || "").trim();
          if (isEvtxECmd && !clientName && row._payloadData1) {
            const cnMatch = row._payloadData1.match(/ClientName:\s*(.+?)(?:\s*$|,)/i);
            if (cnMatch) clientName = cnMatch[1].trim();
          }
          if (isEvtxECmd && !clientAddress && row._payloadData2) {
            const caMatch = row._payloadData2.match(/ClientAddress:\s*(.+?)(?:\s*$|,)/i);
            if (caMatch) clientAddress = caMatch[1].trim();
          }
          sourceHost = clientName ? clientName.toUpperCase() : clientAddress ? clientAddress.toUpperCase() : "";
          sourceFieldType = clientName ? "clientName" : clientAddress ? "ip" : "";

          // Parse user from standard Security format. Same EvtxECmd fallback as
          // the standard branch below: when PayloadData1 lacks "Target:", recover
          // from UserName and strip the SID parenthetical.
          user = row.user || "";
          if (isEvtxECmd && user) {
            const pdMatch = user.match(/^Target:\s*(?:([^\\]+)\\)?(.+)$/i);
            if (pdMatch) {
              user = pdMatch[2].trim();
            } else {
              const fallback = cleanWrappedField(row._userNameFallback || "")
                .replace(/\s*\(S-1-[0-9-]+\)\s*$/i, "")
                .trim();
              if (fallback && fallback !== "-\\-" && fallback !== "-") user = fallback;
              else user = "";
            }
          }

        // === 4776: NTLM authentication — Workstation in PayloadData2 for EvtxECmd ===
        } else if (eventId === "4776") {
          // EvtxECmd mapped format: PD2 = "Workstation: HOSTNAME"
          if (isEvtxECmd && row._payloadData2) {
            const wkMatch = row._payloadData2.match(/Workstation:\s*(.+?)(?:\s*$|,)/i);
            if (wkMatch) { sourceHost = _normLmHost(wkMatch[1]); sourceFieldType = "workstation"; }
          }
          if (!sourceHost && isHayabusa && compact) {
            sourceHost = _normLmHost(compactGet(compact, "Wkst", "Workstation", "SrcComp"));
            if (sourceHost) sourceFieldType = "workstation";
          }
          // Fallback to standard workstation/source columns
          if (!sourceHost || sourceHost === "-") {
            sourceHost = _normLmHost(row.workstation || "");
            if (sourceHost && sourceHost !== "-") { sourceFieldType = "workstation"; }
            else { sourceHost = _normLmHost(row.source || ""); sourceFieldType = "ip"; }
          }
          // Parse user from PD1: "Target: username"
          if (isEvtxECmd && !user && row._payloadData1) {
            const tgtMatch = row._payloadData1.match(/Target:\s*(?:[^\\]+\\)?(.+?)(?:\s*$|,)/i);
            if (tgtMatch) user = tgtMatch[1].trim();
          }

        // === Standard Security event parsing (4624, 4625, 4634, 4647, 4648, 4672) ===
        } else {
          sourceHost = _normLmHost(row.workstation || "");
          if (sourceHost && sourceHost !== "-") { sourceFieldType = "workstation"; }
          else { sourceHost = _normLmHost(row.source || ""); sourceFieldType = "ip"; }

          // EvtxECmd: RemoteHost format is "WorkstationName (IpAddress)"
          if (isEvtxECmd && row.source) {
            const rh = row.source.trim();
            if (/^\*/.test(rh) || /^LOCALSUBNET/i.test(rh) || /^LOCAL$/i.test(rh)) { continue; }
            const rhMatch = rh.match(/^(.+?)\s*\(([^)]+)\)$/);
            if (rhMatch) {
              const wkst = rhMatch[1].trim();
              const ip = rhMatch[2].trim();
              if (wkst && wkst !== "-" && ip && !EXCLUDED_IPS.has(ip)) {
                // Learn IP→hostname mapping for resolving IP-only events later
                _ipToHostname.set(_normLmHost(ip), _normLmHost(wkst));
              }
              sourceHost = (wkst && wkst !== "-") ? _normLmHost(wkst) : _normLmHost(ip);
              sourceFieldType = (wkst && wkst !== "-") ? "workstation" : "ip";
            } else {
              sourceHost = _normLmHost(rh);
            }
          }

          // 4648 (explicit credentials): the forensically meaningful target is the
          // TargetServerName — the remote host the alternate credentials were submitted to
          // (e.g. PsExec/cmdkey/runas to a DC) — NOT the logging Computer. Mirror the Hayabusa
          // TgtSvr handling for the EvtxECmd/raw path; only override when a target name is found
          // (no regression: falls back to Computer when absent).
          if (eventId === "4648" && isEvtxECmd) {
            for (const _pdKey of ["_payloadData1", "_payloadData2", "_payloadData3", "_payloadData4", "_payloadData5"]) {
              const _pdVal = (row[_pdKey] || "").toString();
              if (!_pdVal) continue;
              const _tsvrMatch = _pdVal.match(/Target\s*Server\s*Name[:\s]+([^\s|,]+)/i);
              if (_tsvrMatch) {
                const _tsvr = _tsvrMatch[1].trim();
                if (_tsvr && _tsvr !== "-" && _tsvr.toLowerCase() !== "localhost") targetHost = _normLmHost(_tsvr);
                break;
              }
            }
          }

          // EvtxECmd: PayloadData1 format is "Target: DOMAIN\User". When that prefix
          // is absent (e.g. 4672 "PrivilegeList: ..."), fall back to the UserName
          // column ("DOMAIN\\user (SID)") and strip the trailing SID parenthetical.
          user = cleanWrappedField(row.user || "");
          if (isEvtxECmd && user) {
            const pdMatch = user.match(/^Target:\s*(?:([^\\]+)\\)?(.+)$/i);
            if (pdMatch) {
              user = pdMatch[2].trim();
            } else {
              const fallback = cleanWrappedField(row._userNameFallback || "")
                .replace(/\s*\(S-1-[0-9-]+\)\s*$/i, "")
                .trim();
              if (fallback && fallback !== "-\\-" && fallback !== "-") user = fallback;
              else user = "";
            }
          }

          // EvtxECmd: PayloadData2 format is "LogonType N"
          logonType = cleanWrappedField(row.logonType || "");
          if (isEvtxECmd && logonType) {
            const ltMatch = logonType.match(/LogonType\s+(\d+)/i);
            if (ltMatch) logonType = ltMatch[1];
            else logonType = "";
          }
        }

        if (user && user.includes("\\")) user = user.split("\\").pop();
        user = cleanWrappedField(user);
        if (logonType && !isEvtxECmd) {
          logonType = extractFirstInteger(logonType) || cleanWrappedField(logonType);
        }
        if (!logonType && compact) logonType = extractFirstInteger(compactGet(compact, "Type", "LogonType"));

        // Telemetry coverage: also count this event against the resolved source host (if any)
        if (sourceHost && eventId) _bumpHostTelemetry(sourceHost, eventId);
        // Per-user event counts (raw, pre-filter) — used by Accounts aggregation.
        // ts lets the tracker record the true first-success time per user.
        if (user && eventId) _bumpUserEvent(user, eventId, row.ts || "");

        // Capture every 4672 (admin-privilege-assigned) occurrence for later
        // correlation to scoped 4624 logons (see accounts.js Pass 4b). 4672 carries
        // no source host, so it can't be scoped by the source/local filters — instead
        // it's tied to a logon by (user, host, ~same second), recovering the ADMIN
        // signal for network (type 3) and other non-RDP privileged logons. Captured
        // for ALL 4672; non-lateral users simply never match a scoped 4624.
        if (privLogonEvents && eventId === "4672" && user && targetHost) {
          privLogonEvents.push({ userKey: user.toUpperCase(), host: targetHost, ts: row.ts || "" });
        }

        if (!sourceHost || EXCLUDED_IPS.has(sourceHost) || isExcludedEndpoint(sourceHost)) {
          // Still collect for RDP session correlation if we have target + user (for logoff/disconnect events)
          if (SESSION_ONLY_EVENTS.has(eventId) && targetHost && user) {
            let _drc;
            if (eventId === "40") {
              if (isEvtxECmd) { const m = (row._payloadData3 || row._payloadData2 || "").match(/Reason\s*(?:Code)?:?\s*(\d+)/i); if (m) _drc = m[1]; }
              else if (compact) { _drc = compactGet(compact, "Reason", "ReasonCode") || undefined; }
              if (!_drc) { const r = row._rawReason || row._rawParam3; if (r) _drc = extractFirstInteger(r) || undefined; }
            }
            if (RDP_CONTEXT_EVENT_IDS.has(eventId)) {
              rdpEvents.push({ eventId, ts: row.ts || "", user, sourceHost: "", targetHost, logonType, sessionId, channel: channelNorm || channelRaw, ...(_drc ? { disconnectReasonCode: _drc } : {}), ...provenance });
            }
          }
          continue;
        }
        if (excludeLocalLogons && sourceHost === targetHost) continue;
        if (excludeServiceAccounts && user && (SERVICE_RE.test(user) || user.endsWith("$"))) continue;

        // Scoped per-user counts: this event has a real (non-local) source and a
        // non-service / non-machine user — i.e. it belongs to the lateral-movement
        // population. Bumped here (after the same exclusions that gate timeOrdered /
        // success-fail) so the Accounts tab's privilege/credential counts reconcile
        // with Successes/Failures instead of mixing in host-wide local/service noise.
        // 4672 is excluded — it's scoped separately via (user, host, time) correlation
        // to a scoped 4624 (accounts.js Pass 4b), since 4672 has no source host.
        if (user && eventId && eventId !== "4672") _bumpUserEventScoped(user, eventId);

        const ts = row.ts || "";
        const isFailure = eventId === "4625" || eventId === "4771"; // 4771 = Kerberos pre-auth failed

        // Collect for RDP session correlation
        // Extract EID 40 disconnect reason code while we have access to raw row data
        let disconnectReasonCode;
        if (eventId === "40") {
          if (isEvtxECmd) {
            const m = (row._payloadData3 || row._payloadData2 || "").match(/Reason\s*(?:Code)?:?\s*(\d+)/i);
            if (m) disconnectReasonCode = m[1];
          } else if (compact) {
            disconnectReasonCode = compactGet(compact, "Reason", "ReasonCode") || undefined;
          }
          if (!disconnectReasonCode) {
            // Raw EVTX: check for Param3 or dedicated Reason column
            const rawReason = row._rawReason || row._rawParam3;
            if (rawReason) disconnectReasonCode = extractFirstInteger(rawReason) || undefined;
          }
        }
        if (RDP_CONTEXT_EVENT_IDS.has(eventId)) {
          rdpEvents.push({ eventId, ts, user, sourceHost, targetHost, logonType, sessionId, channel: channelNorm || channelRaw, ...(disconnectReasonCode ? { disconnectReasonCode } : {}), ...provenance });
        }

        // Session-only events: don't create graph edges, only used for RDP session correlation
        if (SESSION_ONLY_EVENTS.has(eventId)) continue;

        // === Build graph edges (edge-creating events only) ===
        if (!hostSet.has(sourceHost)) hostSet.set(sourceHost, { isSource: false, isTarget: false, eventCount: 0 });
        if (!hostSet.has(targetHost)) hostSet.set(targetHost, { isSource: false, isTarget: false, eventCount: 0 });
        hostSet.get(sourceHost).isSource = true;
        hostSet.get(sourceHost).eventCount++;
        hostSet.get(targetHost).isTarget = true;
        hostSet.get(targetHost).eventCount++;

        const edgeKey = `${sourceHost}->${targetHost}`;
        if (!edgeMap.has(edgeKey)) {
          edgeMap.set(edgeKey, { source: sourceHost, target: targetHost, count: 0, users: new Set(), logonTypes: new Set(), firstSeen: ts, lastSeen: ts, hasFailures: false, clientNames: new Set(), clientAddresses: new Set(), eventBreakdown: new Map(), evidenceRefs: [] });
        }
        const edge = edgeMap.get(edgeKey);
        if (evidenceRef) edge.evidenceRefs = _dedupeEvidenceRefs([...(edge.evidenceRefs || []), evidenceRef]);
        // Track share access for 5140/5145 events separately from core logon/session count
        let shareName = "";
        let relativeTargetName = "";
        const isShareEvt = eventId === "5140" || eventId === "5145";
        if (isShareEvt) {
          edge.shareAccessCount = (edge.shareAccessCount || 0) + 1;
          shareName = (row.shareName || "").trim();
          // EvtxECmd: share name may be in PayloadData fields
          if (!shareName && isEvtxECmd) {
            for (const pdKey of ["_payloadData1", "_payloadData2", "_payloadData3"]) {
              const pdVal = (row[pdKey] || "").toString();
              const snMatch = pdVal.match(/ShareName[:\s]+([^\s|,]+)/i) || pdVal.match(/\\\\[^\\]+\\([^\s|,]+)/);
              if (snMatch) { shareName = snMatch[1].trim(); break; }
            }
          } else if (!shareName && compact) {
            shareName = compactGet(compact, "ShareName", "Share");
          }
          if (shareName) {
            if (!edge.shareNames) edge.shareNames = new Set();
            edge.shareNames.add(shareName);
            const sn = shareName.replace(/^\\\\\*\\/, "").toUpperCase();
            if (/^(ADMIN\$|C\$|[A-Z]\$)$/.test(sn)) edge._adminShareCount = (edge._adminShareCount || 0) + 1;
          }
          // 5145 RelativeTargetName: the named pipe / file accessed over the share — the single
          // most specific SMB lateral-movement signal (svcctl = remote service control / PsExec,
          // atsvc = remote scheduled task, winreg = remote registry, PSEXESVC.exe = tool drop).
          if (eventId === "5145") {
            relativeTargetName = (row.relativeTargetName || "").trim();
            if (!relativeTargetName && isEvtxECmd) {
              for (const pdKey of ["_payloadData1", "_payloadData2", "_payloadData3", "_payloadData4", "_payloadData5"]) {
                const pdVal = (row[pdKey] || "").toString();
                const rtnMatch = pdVal.match(/Relative\s*Target\s*Name[:\s]+([^\s|,]+)/i);
                if (rtnMatch) { relativeTargetName = rtnMatch[1].trim(); break; }
              }
            } else if (!relativeTargetName && compact) {
              relativeTargetName = compactGet(compact, "RelativeTargetName", "RelativeTarget") || "";
            }
          }
        } else {
          edge.count++; // core logon/session events only
        }
        if (user) edge.users.add(user);
        if (logonType) edge.logonTypes.add(logonType);
        if (logonType === "10" || logonType === "12") edge._rdpLogonCount = (edge._rdpLogonCount || 0) + 1;
        if (ts && ts < edge.firstSeen) edge.firstSeen = ts;
        if (ts && ts > edge.lastSeen) edge.lastSeen = ts;
        if (isFailure) edge.hasFailures = true;
        if (clientName) edge.clientNames.add(clientName);
        if (clientAddress && clientAddress !== "LOCAL") edge.clientAddresses.add(clientAddress);
        if (eventId) edge.eventBreakdown.set(eventId, (edge.eventBreakdown.get(eventId) || 0) + 1);

        // Parse SubStatus for 4625 failure reason context
        let subStatus = undefined;
        if (eventId === "4625") {
          if (row.subStatus) {
            subStatus = row.subStatus.toString().trim();
          } else if (compact) {
            subStatus = compactGet(compact, "SubStatus");
            if (subStatus) subStatus = subStatus.toUpperCase();
          } else if (isEvtxECmd) {
            // EvtxECmd: SubStatus often in PayloadData3 or PayloadData4 as "SubStatus: 0xC000006A"
            for (const pdKey of ["_payloadData3", "_payloadData4", "_payloadData5"]) {
              const pdVal = (row[pdKey] || "").toString();
              const ssMatch = pdVal.match(/Sub\s*Status[:\s]+(0x[0-9A-Fa-f]+)/i);
              if (ssMatch) { subStatus = ssMatch[1].toUpperCase(); break; }
            }
          }
        } else if (eventId === "4771") {
          // 4771 carries a Kerberos failure code (short hex like 0x18) instead of an NT SubStatus.
          // Capture it so the brute-force noise dampener can distinguish benign lockout/expiry
          // bursts (revoked/expired/clock-skew) from real password guessing (bad password / no user).
          if (row.subStatus) {
            subStatus = row.subStatus.toString().trim().toUpperCase();
          } else if (compact) {
            subStatus = compactGet(compact, "Status", "FailureCode", "ResultCode");
            if (subStatus) subStatus = subStatus.toUpperCase();
          } else if (isEvtxECmd) {
            for (const pdKey of ["_payloadData1", "_payloadData2", "_payloadData3", "_payloadData4", "_payloadData5"]) {
              const pdVal = (row[pdKey] || "").toString();
              const kcMatch = pdVal.match(/(?:Failure\s*Code|Status|Result\s*Code)[:\s]+(0x[0-9A-Fa-f]+)/i);
              if (kcMatch) { subStatus = kcMatch[1].toUpperCase(); break; }
            }
          }
          // Raw EVTX names this field Status, not SubStatus, so the dedicated
          // subStatus column is empty and the brute-force severity stayed capped
          // at medium regardless of the actual Kerberos failure code.
          if (!subStatus && row._statusCol) subStatus = row._statusCol.toString().trim().toUpperCase();
        }

        timeOrdered.push({ source: sourceHost, target: targetHost, user, ts, logonType, eventId, shareName: shareName || undefined, relativeTargetName: relativeTargetName || undefined, subStatus, sourceFieldType, ...provenance });
      }

      // === IP-to-Hostname Resolution ===
      // When EvtxECmd "WorkstationName (IpAddress)" or 4776 Workstation fields provide both
      // a hostname and IP for the same source, merge IP-only graph nodes into their hostname.
      if (_ipToHostname.size > 0) {
        // Resolve IP sources in timeOrdered events
        for (const evt of timeOrdered) {
          if (evt.sourceFieldType === "ip" && _ipToHostname.has(evt.source)) {
            evt.source = _ipToHostname.get(evt.source);
            evt.sourceFieldType = "resolved";
          }
        }
        // The session state machine consumes a separate event array. Leaving it on
        // raw IPs while the graph moved to hostnames split one real connection into
        // two identities and prevented lifecycle events from joining.
        for (const evt of rdpEvents) {
          if (evt.sourceHost && _ipToHostname.has(evt.sourceHost)) {
            evt.sourceHost = _ipToHostname.get(evt.sourceHost);
          }
        }
        // Merge IP edges into hostname edges in edgeMap
        for (const [ip, hostname] of _ipToHostname) {
          const ipEdges = [];
          for (const [key, edge] of edgeMap) {
            if (edge.source === ip) ipEdges.push([key, edge]);
          }
          for (const [ipKey, ipEdge] of ipEdges) {
            const hostnameKey = `${hostname}->${ipEdge.target}`;
            const existing = edgeMap.get(hostnameKey);
            if (existing) {
              // Merge into existing hostname edge
              existing.count += ipEdge.count;
              for (const u of ipEdge.users) existing.users.add(u);
              for (const lt of ipEdge.logonTypes) existing.logonTypes.add(lt);
              for (const cn of ipEdge.clientNames) existing.clientNames.add(cn);
              for (const ca of ipEdge.clientAddresses) existing.clientAddresses.add(ca);
              if (ipEdge.firstSeen < existing.firstSeen) existing.firstSeen = ipEdge.firstSeen;
              if (ipEdge.lastSeen > existing.lastSeen) existing.lastSeen = ipEdge.lastSeen;
              if (ipEdge.hasFailures) existing.hasFailures = true;
              for (const [eid, cnt] of ipEdge.eventBreakdown) existing.eventBreakdown.set(eid, (existing.eventBreakdown.get(eid) || 0) + cnt);
              existing.shareAccessCount = (existing.shareAccessCount || 0) + (ipEdge.shareAccessCount || 0);
              existing._adminShareCount = (existing._adminShareCount || 0) + (ipEdge._adminShareCount || 0);
              existing._rdpLogonCount = (existing._rdpLogonCount || 0) + (ipEdge._rdpLogonCount || 0);
              existing.evidenceRefs = _dedupeEvidenceRefs([...(existing.evidenceRefs || []), ...(ipEdge.evidenceRefs || [])]);
              if (ipEdge.shareNames) { if (!existing.shareNames) existing.shareNames = new Set(); for (const sn of ipEdge.shareNames) existing.shareNames.add(sn); }
            } else {
              // Rename the edge
              edgeMap.set(hostnameKey, { ...ipEdge, source: hostname });
            }
            edgeMap.delete(ipKey);
          }
          // Merge hostSet entries
          if (hostSet.has(ip)) {
            const ipInfo = hostSet.get(ip);
            if (hostSet.has(hostname)) {
              const hnInfo = hostSet.get(hostname);
              hnInfo.eventCount += ipInfo.eventCount;
              if (ipInfo.isSource) hnInfo.isSource = true;
              if (ipInfo.isTarget) hnInfo.isTarget = true;
            } else {
              hostSet.set(hostname, ipInfo);
            }
            hostSet.delete(ip);
          }
        }
      }

      // === Conservative short-name/FQDN alias resolution ===
      // Merge only when BOTH forms were observed and one short name maps to exactly
      // one FQDN. This fixes "WKS01" and "WKS01.corp.example" appearing as separate
      // graph nodes without collapsing same-named hosts from two domains.
      {
        const aliases = buildObservedHostAliases([
          ...hostSet.keys(),
          ...timeOrdered.flatMap((evt) => [evt.source, evt.target]),
          ...rdpEvents.flatMap((evt) => [evt.sourceHost, evt.targetHost]),
        ]);
        if (aliases.size > 0) {
          const canonical = (host) => aliases.get(host) || host;
          for (const evt of timeOrdered) {
            evt.source = canonical(evt.source);
            evt.target = canonical(evt.target);
          }
          for (const evt of rdpEvents) {
            evt.sourceHost = canonical(evt.sourceHost);
            evt.targetHost = canonical(evt.targetHost);
          }

          const mergedHosts = new Map();
          for (const [host, info] of hostSet) {
            const id = canonical(host);
            const current = mergedHosts.get(id) || {
              isSource: false,
              isTarget: false,
              eventCount: 0,
              aliases: new Set(),
            };
            current.isSource = current.isSource || !!info.isSource;
            current.isTarget = current.isTarget || !!info.isTarget;
            current.eventCount += Number(info.eventCount) || 0;
            if (host !== id) current.aliases.add(host);
            for (const alias of (info.aliases || [])) current.aliases.add(alias);
            mergedHosts.set(id, current);
          }
          hostSet.clear();
          for (const [id, info] of mergedHosts) hostSet.set(id, info);

          const mergeEdge = (target, source) => {
            target.count += source.count || 0;
            target.shareAccessCount = (target.shareAccessCount || 0) + (source.shareAccessCount || 0);
            target._adminShareCount = (target._adminShareCount || 0) + (source._adminShareCount || 0);
            target._rdpLogonCount = (target._rdpLogonCount || 0) + (source._rdpLogonCount || 0);
            target.hasFailures = target.hasFailures || source.hasFailures;
            if (source.firstSeen && (!target.firstSeen || source.firstSeen < target.firstSeen)) target.firstSeen = source.firstSeen;
            if (source.lastSeen && (!target.lastSeen || source.lastSeen > target.lastSeen)) target.lastSeen = source.lastSeen;
            for (const value of source.users || []) target.users.add(value);
            for (const value of source.logonTypes || []) target.logonTypes.add(value);
            for (const value of source.clientNames || []) target.clientNames.add(value);
            for (const value of source.clientAddresses || []) target.clientAddresses.add(value);
            for (const value of source.shareNames || []) {
              if (!target.shareNames) target.shareNames = new Set();
              target.shareNames.add(value);
            }
            for (const [eid, count] of source.eventBreakdown || []) {
              target.eventBreakdown.set(eid, (target.eventBreakdown.get(eid) || 0) + count);
            }
            target.evidenceRefs = _dedupeEvidenceRefs([
              ...(target.evidenceRefs || []),
              ...(source.evidenceRefs || []),
            ]);
          };
          const mergedEdges = new Map();
          for (const edge of edgeMap.values()) {
            const source = canonical(edge.source);
            const target = canonical(edge.target);
            if (!source || !target || source === target) continue;
            const key = `${source}->${target}`;
            const existing = mergedEdges.get(key);
            if (existing) mergeEdge(existing, edge);
            else mergedEdges.set(key, { ...edge, source, target });
          }
          edgeMap.clear();
          for (const [key, edge] of mergedEdges) edgeMap.set(key, edge);

          if (hostTelemetry instanceof Map) {
            const mergedTelemetry = new Map();
            for (const [host, eidMap] of hostTelemetry) {
              const id = canonical(host);
              if (!mergedTelemetry.has(id)) mergedTelemetry.set(id, new Map());
              const targetMap = mergedTelemetry.get(id);
              for (const [eid, count] of eidMap) {
                targetMap.set(eid, (targetMap.get(eid) || 0) + count);
              }
            }
            hostTelemetry.clear();
            for (const [host, eidMap] of mergedTelemetry) hostTelemetry.set(host, eidMap);
          }
        }
      }

      // === RDP Session Correlation ===
      const _tsMs = (value) => {
        const parsed = normalizeTimestamp(value);
        return Number.isFinite(parsed) ? parsed : null;
      };
      const _cmpTs = (a, b) => {
        const am = _tsMs(a);
        const bm = _tsMs(b);
        if (am != null && bm != null) return am - bm;
        return String(a || "").localeCompare(String(b || ""));
      };
      rdpEvents.sort((a, b) => _cmpTs(a.ts, b.ts));
      const rdpSessions = [];
      const openSessions = new Map(); // unique open key -> session
      const openByBase = new Map(); // source->target|user -> Set<open key>
      const openByTargetUser = new Map(); // target|user -> Set<open key>
      const openBySessionId = new Map(); // target|user|sid -> Set<open key>

      const _baseKeyFor = (evt) => `${evt.sourceHost || "?"}->${evt.targetHost}|${evt.user}`;
      const _targetUserKeyFor = (evt) => `${evt.targetHost}|${evt.user}`;
      const _sessionIdentityKeyFor = (evt) => evt.sessionId
        ? `${_targetUserKeyFor(evt)}|s${evt.sessionId}`
        : "";
      const _indexOpen = (index, key, openKey) => {
        if (!key) return;
        if (!index.has(key)) index.set(key, new Set());
        index.get(key).add(openKey);
      };
      const _unindexOpen = (index, key, openKey) => {
        const set = index.get(key);
        if (!set) return;
        set.delete(openKey);
        if (set.size === 0) index.delete(key);
      };
      const _registerOpenSession = (session, evt) => {
        const baseKey = _baseKeyFor(evt);
        const targetUserKey = _targetUserKeyFor(evt);
        const sessionIdentityKey = _sessionIdentityKeyFor(evt);
        const openKey = `${baseKey}${evt.sessionId ? `|s${evt.sessionId}` : ""}|#${session.id}`;
        session._openKey = openKey;
        session._openBaseKey = baseKey;
        session._openTargetUserKey = targetUserKey;
        session._openSessionIdentityKey = sessionIdentityKey;
        openSessions.set(openKey, session);
        _indexOpen(openByBase, baseKey, openKey);
        _indexOpen(openByTargetUser, targetUserKey, openKey);
        _indexOpen(openBySessionId, sessionIdentityKey, openKey);
      };
      const _closeOpenSession = (session) => {
        if (!session?._openKey) return;
        openSessions.delete(session._openKey);
        _unindexOpen(openByBase, session._openBaseKey, session._openKey);
        _unindexOpen(openByTargetUser, session._openTargetUserKey, session._openKey);
        _unindexOpen(openBySessionId, session._openSessionIdentityKey, session._openKey);
        delete session._openKey;
        delete session._openBaseKey;
        delete session._openTargetUserKey;
        delete session._openSessionIdentityKey;
      };
      const _findOpenSession = (evt, windowMs) => {
        const candidateKeys = new Set();
        for (const key of (openByBase.get(_baseKeyFor(evt)) || [])) candidateKeys.add(key);
        for (const key of (openByTargetUser.get(_targetUserKeyFor(evt)) || [])) candidateKeys.add(key);
        for (const key of (openBySessionId.get(_sessionIdentityKeyFor(evt)) || [])) candidateKeys.add(key);
        let best = null;
        let bestStrength = Infinity;
        let bestDiff = Infinity;
        for (const key of candidateKeys) {
          const session = openSessions.get(key);
          if (!session) continue;
          if (String(session.target || "") !== String(evt.targetHost || "")) continue;
          if (String(session.user || "").toUpperCase() !== String(evt.user || "").toUpperCase()) continue;
          const sameSid = !!evt.sessionId && !!session.sessionId && String(evt.sessionId) === String(session.sessionId);
          if (evt.sessionId && session.sessionId && !sameSid) continue;
          const sameSource = !!evt.sourceHost && !!session.source
            && String(evt.sourceHost).toUpperCase() === String(session.source).toUpperCase();
          if (evt.sourceHost && session.source && !sameSource && !sameSid) continue;
          const lastEvt = session.events[session.events.length - 1];
          const eventMs = _tsMs(evt.ts);
          const lastMs = _tsMs(lastEvt?.ts || session.startTime);
          const diff = eventMs != null && lastMs != null ? eventMs - lastMs : 0;
          if (diff < 0) continue;
          // A matching TerminalServices SessionId is authoritative across a long
          // session; source/target/user-only correlation stays tightly bounded.
          const allowed = sameSid ? 7 * 86400000 : windowMs;
          if (diff > allowed) continue;
          const strength = sameSid ? 0 : sameSource ? 1 : 2;
          if (strength < bestStrength || (strength === bestStrength && diff < bestDiff)) {
            best = session;
            bestStrength = strength;
            bestDiff = diff;
          }
        }
        return best;
      };
      const _rdpSessionEvent = (evt, description, logonType = "") => ({
        eventId: evt.eventId,
        ts: evt.ts,
        description,
        logonType,
        evidenceRefs: _dedupeEvidenceRefs(evt.evidenceRefs || []),
      });
      const _pushRdpSessionEvent = (session, evt, description, logonType = "") => {
        session.events.push(_rdpSessionEvent(evt, description, logonType));
        session.evidenceRefs = _dedupeEvidenceRefs([...(session.evidenceRefs || []), ...(evt.evidenceRefs || [])]);
        session.itemRowids = _rowidsFromRefs(session.evidenceRefs);
      };
      const _newRdpSession = (evt, overrides = {}, registerOpen = true) => {
        const session = {
          id: rdpSessions.length,
          source: evt.sourceHost || "",
          target: evt.targetHost,
          user: evt.user,
          sessionId: evt.sessionId || "",
          events: [],
          startTime: evt.ts,
          endTime: null,
          status: "connecting",
          isReconnect: false,
          hasAdmin: false,
          hasFailed: false,
          evidenceLevel: "direct",
          evidenceBasis: [],
          evidenceRefs: [],
          itemRowids: [],
          ...overrides,
        };
        rdpSessions.push(session);
        if (registerOpen) _registerOpenSession(session, evt);
        return session;
      };

      // Security 4625 Type 3 means "network logon failure", not "RDP failure".
      // It is admitted to the RDP activity table only when direct RDP telemetry
      // on the same source->target pair occurs nearby. Types 10/12 are direct.
      const _DIRECT_RDP_SIGNAL_EIDS = new Set(["20", "21", "22", "23", "24", "25", "32", "33", "34", "35", "39", "40", "1149", "4778", "4779"]);
      const _directRdpSignalsByPair = new Map();
      for (const evt of rdpEvents) {
        const directSecurity = evt.eventId === "4624" && ["10", "12"].includes(evt.logonType);
        if (!_DIRECT_RDP_SIGNAL_EIDS.has(evt.eventId) && !directSecurity) continue;
        if (!evt.sourceHost || !evt.targetHost) continue;
        const key = `${evt.sourceHost}->${evt.targetHost}`;
        if (!_directRdpSignalsByPair.has(key)) _directRdpSignalsByPair.set(key, []);
        _directRdpSignalsByPair.get(key).push(evt);
      }
      const _nearbyRdpSignal = (evt, windowMs = 600000) => {
        if (!evt.sourceHost || !evt.targetHost || !evt.ts) return null;
        const eventMs = _tsMs(evt.ts);
        if (eventMs == null) return null;
        const pair = `${evt.sourceHost}->${evt.targetHost}`;
        let best = null;
        let bestGap = Infinity;
        for (const signal of (_directRdpSignalsByPair.get(pair) || [])) {
          const signalMs = _tsMs(signal.ts);
          if (signalMs == null) continue;
          const gap = Math.abs(signalMs - eventMs);
          if (gap <= windowMs && gap < bestGap) {
            best = signal;
            bestGap = gap;
          }
        }
        return best;
      };
      const _rdpFailureEvidence = (evt) => {
        if (["10", "12"].includes(String(evt.logonType || ""))) {
          return { level: "direct", basis: `Security 4625 Logon Type ${evt.logonType}` };
        }
        if (String(evt.logonType || "") === "3") {
          const signal = _nearbyRdpSignal(evt);
          if (signal) {
            return {
              level: "correlated",
              basis: `Security 4625 Type 3 correlated with TerminalServices ${signal.eventId} on the same pair`,
              signal,
            };
          }
        }
        return null;
      };

      for (const evt of rdpEvents) {
        const eid = evt.eventId;
        const desc = (eid === "4624" && evt.logonType === "10") ? "RDP logon succeeded"
          : (eid === "4624" && evt.logonType === "7") ? "Reconnect logon"
          : (eid === "4624" && evt.logonType === "12") ? "Cached RDP logon"
          : RDP_EVENT_DESC[eid] || `Event ${eid}`;

        // Connection-starting events
        const type7Signal = eid === "4624" && evt.logonType === "7" ? _nearbyRdpSignal(evt, 120000) : null;
        if (eid === "1149" || (eid === "4624" && ["10","12"].includes(evt.logonType)) || type7Signal) {
          let session = _findOpenSession(evt, eid === "1149" ? 5000 : 120000);
          if (!session) {
            session = _newRdpSession(evt, {
              isReconnect: evt.logonType === "7",
              evidenceLevel: type7Signal ? "correlated" : "direct",
              evidenceBasis: [
                type7Signal
                  ? `Security 4624 Type 7 correlated with TerminalServices ${type7Signal.eventId}`
                  : eid === "1149"
                    ? "TerminalServices RemoteConnectionManager 1149"
                    : `Security 4624 Logon Type ${evt.logonType}`,
              ],
            });
          }
          _pushRdpSessionEvent(session, evt, desc, evt.logonType || "");
        }
        // Session-active events: 21, 22, 25
        else if (["21","22","25"].includes(eid)) {
          let session = _findOpenSession(evt, 120000);
          // LocalSessionManager 21 (session logon) and 25 (reconnect) are themselves session
          // starts. They only ever attached to an existing session because 1149 was assumed
          // present — true when RemoteConnectionManager is imported alongside, false when the
          // analyst has only the LSM channel or RCM was an empty stub. Without this, a
          // populated LocalSessionManager log yields no sessions at all. 22 stays
          // attach-only: a shell-start with no preceding logon is not a session.
          if (!session && (eid === "21" || eid === "25")) {
            session = _newRdpSession(evt, {
              isReconnect: eid === "25",
              evidenceBasis: [`TerminalServices LocalSessionManager ${eid}`],
            });
          }
          if (session) {
            session.status = "active";
            _pushRdpSessionEvent(session, evt, desc, evt.logonType || "");
            if (eid === "25") session.isReconnect = true;
          }
        }
        // Admin privilege: 4672
        else if (eid === "4672") {
          const session = _findOpenSession(evt, 5000);
          if (session) {
            session.hasAdmin = true;
            _pushRdpSessionEvent(session, evt, desc, "");
          }
        }
        // Disconnect events: 24, 39, 40, 4779
        else if (["24","39","40","4779"].includes(eid)) {
          const session = _findOpenSession(evt, 86400000);
          if (session) {
            session.status = "disconnected";
            let evtDesc = desc;
            // EID 40: decode disconnect reason codes for forensic context
            if (eid === "40" && evt.disconnectReasonCode) {
              const EID40_REASONS = { "0": "No additional info", "1": "User request", "2": "Admin disconnect", "3": "Idle timeout", "5": "Replaced by another connection", "6": "Out of memory", "7": "Server denied connection", "9": "Client decompress error", "11": "User-initiated disconnect", "12": "Server-initiated disconnect" };
              const reasonText = EID40_REASONS[evt.disconnectReasonCode] || `Code ${evt.disconnectReasonCode}`;
              evtDesc = `${desc} [${reasonText}]`;
              session.disconnectReason = reasonText;
              session.disconnectReasonCode = evt.disconnectReasonCode;
              if (evt.disconnectReasonCode === "5") session.replacedByAnotherSession = true;
            }
            _pushRdpSessionEvent(session, evt, evtDesc, "");
          }
        }
        // Shadow/mirror events: 20, 32, 33, 34, 35 (TerminalServices)
        // EID 20 = session logon failed, 32 = session begin shadow,
        // 33 = session end shadow, 34 = session logon, 35 = session reconnection failure
        else if (["20","32","33","34","35"].includes(eid)) {
          const session = _findOpenSession(evt, 120000);
          if (session) {
            if (eid === "32") { session.isShadowed = true; session.status = "active"; }
            if (eid === "20" || eid === "35") session.hasFailed = true;
            _pushRdpSessionEvent(session, evt, desc + (eid === "32" ? " [SHADOW BEGIN]" : eid === "33" ? " [SHADOW END]" : ""), "");
          }
        }
        // Logoff events: 23, 4634, 4647
        else if (["23","4634","4647"].includes(eid)) {
          const session = _findOpenSession(evt, 86400000);
          if (session) {
            session.status = "ended";
            session.endTime = evt.ts;
            _pushRdpSessionEvent(session, evt, desc, "");
            _closeOpenSession(session);
          }
        }
        // Failed logon: 4625
        else if (eid === "4625") {
          const evidence = _rdpFailureEvidence(evt);
          if (!evidence) continue;
          const correlationRefs = evidence.signal?.evidenceRefs || [];
          const session = _newRdpSession(evt, {
            sessionId: "",
            endTime: evt.ts,
            status: "failed",
            hasFailed: true,
            evidenceLevel: evidence.level,
            evidenceBasis: [evidence.basis],
            evidenceRefs: _dedupeEvidenceRefs([...(evt.evidenceRefs || []), ...correlationRefs]),
          }, false);
          _pushRdpSessionEvent(session, evt, desc, evt.logonType || "");
          session.evidenceRefs = _dedupeEvidenceRefs([...session.evidenceRefs, ...correlationRefs]);
          session.itemRowids = _rowidsFromRefs(session.evidenceRefs);
        }
        // 4648: explicit creds, 4778: reconnect
        else if (eid === "4648" || eid === "4778") {
          let session = _findOpenSession(evt, eid === "4778" ? 86400000 : 30000);
          if (!session && eid === "4778") {
            session = _newRdpSession(evt, {
              isReconnect: true,
              evidenceBasis: ["Security 4778 window-station reconnect"],
            });
          }
          if (session) {
            _pushRdpSessionEvent(session, evt, desc, "");
            if (eid === "4778") { session.isReconnect = true; session.status = "active"; }
          }
        }
      }
      // Mark remaining open sessions
      for (const session of [...new Set(openSessions.values())]) {
        if (session.status === "connecting" || session.status === "active") {
          session.status = session.events.length > 1 ? "active (no logoff)" : "incomplete";
        }
        _closeOpenSession(session);
      }

      // === Failed Session Clustering ===
      // Collapse standalone 4625 events with same source→target→user within 5 min into one row
      const FAIL_CLUSTER_MS = 300000;
      const _failedStandalone = [];
      const _keptSessions = [];
      for (const s of rdpSessions) {
        if (s.status === "failed" && s.events.length === 1 && s.events[0].eventId === "4625") {
          _failedStandalone.push(s);
        } else {
          s.attemptCount = 1;
          _keptSessions.push(s);
        }
      }
      _failedStandalone.sort((a, b) => {
        const ka = `${a.source}|${a.target}|${a.user}`, kb = `${b.source}|${b.target}|${b.user}`;
        return ka < kb ? -1 : ka > kb ? 1 : _cmpTs(a.startTime, b.startTime);
      });
      let _fci = 0;
      while (_fci < _failedStandalone.length) {
        const anchor = _failedStandalone[_fci];
        const cKey = `${anchor.source}|${anchor.target}|${anchor.user}`;
        const cEvts = [...anchor.events];
        const cSessions = [anchor];
        let cEnd = _fci + 1;
        const anchorMs = _tsMs(anchor.startTime);
        while (cEnd < _failedStandalone.length) {
          const next = _failedStandalone[cEnd];
          if (`${next.source}|${next.target}|${next.user}` !== cKey) break;
          const nextMs = _tsMs(next.startTime);
          // Fixed five-minute episode from the first failure. A rolling window
          // could merge one attempt every 4m59s into a multi-hour "burst".
          if (anchorMs == null || nextMs == null || nextMs - anchorMs > FAIL_CLUSTER_MS) break;
          cEvts.push(...next.events);
          cSessions.push(next);
          cEnd++;
        }
        const last = _failedStandalone[cEnd - 1];
        const clusteredRefs = _dedupeEvidenceRefs(cSessions.flatMap((s) => s.evidenceRefs || []));
        const evidenceBasis = [...new Set(cSessions.flatMap((s) => s.evidenceBasis || []))];
        _keptSessions.push({
          id: 0, source: anchor.source, target: anchor.target, user: anchor.user,
          sessionId: "", events: cEvts,
          startTime: anchor.startTime, endTime: last.startTime,
          status: "failed", isReconnect: false, hasAdmin: false, hasFailed: true,
          attemptCount: cEnd - _fci,
          evidenceLevel: cSessions.some((s) => s.evidenceLevel === "direct") ? "direct" : "correlated",
          evidenceBasis,
          evidenceRefs: clusteredRefs,
          itemRowids: _rowidsFromRefs(clusteredRefs),
        });
        _fci = cEnd;
      }
      _keptSessions.sort((a, b) => _cmpTs(a.startTime, b.startTime));
      _keptSessions.forEach((s, i) => s.id = i);
      rdpSessions.length = 0;
      rdpSessions.push(..._keptSessions);

      // === Session Confidence ===
      for (const s of rdpSessions) {
        const eids = new Set(s.events.map(e => e.eventId));
        const has1149 = eids.has("1149");
        const has4624t10 = s.events.some(e => e.eventId === "4624" && ["10", "7", "12"].includes(e.logonType));
        const has2122 = eids.has("21") || eids.has("22");
        const chainParts = (has1149 ? 1 : 0) + (has4624t10 ? 1 : 0) + (has2122 ? 1 : 0);

        if (chainParts >= 3) s.confidence = "high";
        else if (chainParts >= 2) s.confidence = "medium";
        else if (has4624t10 || has2122) s.confidence = "medium";
        else if (s.status === "failed" && s.evidenceLevel === "direct") s.confidence = "medium";
        else if (s.status === "failed" && (s.attemptCount || 1) >= 3 && s.evidenceLevel === "correlated") s.confidence = "medium";
        else s.confidence = "low";

        // Missing expected events
        s.missingExpected = [];
        if (s.status !== "failed") {
          if (!has1149 && (has4624t10 || has2122)) s.missingExpected.push("1149");
          if (has1149 && !has4624t10 && !eids.has("4625")) s.missingExpected.push("4624");
          if ((has1149 || has4624t10) && !has2122) s.missingExpected.push("21/22");
        }
      }

      // === Reconnect Merging ===
      const RECONNECT_ONLY_EIDS = new Set(["25", "4778", "21", "22", "24", "39", "40"]);
      const RECONNECT_MAX_GAP_MS = 8 * 3600000; // 8 hours
      const _toRemoveIds = new Set();
      for (const s of rdpSessions) {
        if (!s.isReconnect || s.status === "failed") continue;
        const isReconnOnly = s.events.every(e => RECONNECT_ONLY_EIDS.has(e.eventId));
        if (!isReconnOnly) continue;
        let bestParent = null, bestGap = Infinity;
        for (const p of rdpSessions) {
          if (p === s || _toRemoveIds.has(p.id)) continue;
          if ((p.source || "").toUpperCase() !== (s.source || "").toUpperCase()) continue;
          if ((p.target || "").toUpperCase() !== (s.target || "").toUpperCase()) continue;
          if ((p.user || "").toUpperCase() !== (s.user || "").toUpperCase()) continue;
          if (p.isReconnect && p.events.every(e => RECONNECT_ONLY_EIDS.has(e.eventId))) continue;
          if (!p.startTime || !s.startTime || _cmpTs(p.startTime, s.startTime) >= 0) continue;
          const pLastTs = p.events[p.events.length - 1]?.ts || p.endTime || p.startTime;
          const sStartMs = _tsMs(s.startTime);
          const parentLastMs = _tsMs(pLastTs);
          const gap = sStartMs != null && parentLastMs != null ? sStartMs - parentLastMs : NaN;
          if (!Number.isFinite(gap) || gap < 0 || gap > RECONNECT_MAX_GAP_MS) continue;
          if (gap < bestGap) { bestParent = p; bestGap = gap; }
        }
        if (bestParent) {
          bestParent.events.push(...s.events);
          bestParent.events.sort((a, b) => _cmpTs(a.ts, b.ts));
          bestParent.evidenceRefs = _dedupeEvidenceRefs([...(bestParent.evidenceRefs || []), ...(s.evidenceRefs || [])]);
          bestParent.itemRowids = _rowidsFromRefs(bestParent.evidenceRefs);
          bestParent.evidenceBasis = [...new Set([
            ...(bestParent.evidenceBasis || []),
            ...(s.evidenceBasis || []),
          ])];
          const sEnd = s.endTime || s.events[s.events.length - 1]?.ts;
          if (sEnd && (!bestParent.endTime || _cmpTs(sEnd, bestParent.endTime) > 0)) bestParent.endTime = sEnd;
          bestParent.isReconnect = true;
          bestParent.mergedReconnects = (bestParent.mergedReconnects || 0) + 1;
          if (s.status === "active" || s.status === "active (no logoff)") bestParent.status = s.status;
          _toRemoveIds.add(s.id);
        }
      }
      if (_toRemoveIds.size > 0) {
        const filtered = rdpSessions.filter(s => !_toRemoveIds.has(s.id));
        rdpSessions.length = 0;
        rdpSessions.push(...filtered);
        rdpSessions.forEach((s, i) => s.id = i);
      }

      // === Pre-Auth Event Correlation ===
      // Tie 4648 (explicit creds) and 4776 (NTLM validation) events that occur within
      // 10 seconds before an RDP session start to that specific session.
      // These events fire for ALL authentication (SMB, SQL, etc.), not just RDP.
      // Only retain pre-auth events that temporally correlate with an actual RDP session.
      const PRE_AUTH_EIDS = new Set(["4648", "4776"]);
      const PRE_AUTH_WINDOW_MS = 10000; // 10 seconds before session start
      const preAuthEvents = rdpEvents.filter(e => PRE_AUTH_EIDS.has(e.eventId));
      for (const pa of preAuthEvents) {
        if (!pa.ts) continue;
        const paTime = _tsMs(pa.ts);
        if (paTime == null) continue;
        // Find the best matching RDP session: same user + target, starts within 10s after pre-auth
        let bestSession = null, bestGap = Infinity;
        for (const s of rdpSessions) {
          if (s.status === "failed" && s.events.length === 1) continue; // skip isolated failures
          if (!s.startTime) continue;
          const sTime = _tsMs(s.startTime);
          if (sTime == null) continue;
          const gap = sTime - paTime; // session starts AFTER pre-auth
          if (gap < 0 || gap > PRE_AUTH_WINDOW_MS) continue;
          // Match by user (case-insensitive) — IP/hostname matching is too fragile across formats
          const paUser = (pa.user || "").toUpperCase().replace(/.*\\/, "");
          const sUser = (s.user || "").toUpperCase().replace(/.*\\/, "");
          if (paUser && sUser && paUser !== sUser) continue;
          if (gap < bestGap) { bestSession = s; bestGap = gap; }
        }
        if (bestSession) {
          const evtDesc = pa.eventId === "4648" ? "Explicit credential submission (pre-auth)" : "NTLM credential validation (pre-auth)";
          _pushRdpSessionEvent(bestSession, pa, evtDesc, "");
          bestSession.events.sort((a, b) => _cmpTs(a.ts, b.ts));
          if (!bestSession.preAuthEvents) bestSession.preAuthEvents = [];
          bestSession.preAuthEvents.push({ eventId: pa.eventId, ts: pa.ts, sourceHost: pa.sourceHost, gap: bestGap, evidenceRefs: _dedupeEvidenceRefs(pa.evidenceRefs || []) });
        }
      }

      // Recompute effectiveEnd after reconnect merge + pre-auth correlation
      // (those passes can add new events to a session, shifting the last-seen timestamp)
      for (const s of rdpSessions) {
        let lastTs = s.endTime || "";
        for (const evt of s.events) {
          if (evt.ts && (!lastTs || _cmpTs(evt.ts, lastTs) > 0)) lastTs = evt.ts;
        }
        s.effectiveEnd = lastTs || s.startTime || "";
        s.endIsLastSeen = !s.endTime && s.effectiveEnd !== s.startTime;
      }

      // === Technique Assignment ===
      for (const s of rdpSessions) {
        s.mergedReconnects = s.mergedReconnects || 0;
        if (s.status === "failed") {
          s.technique = (s.attemptCount || 1) >= 5 ? "RDP Brute Force" : "RDP Failed Auth";
        } else if (s.isReconnect) {
          s.technique = "RDP Reconnect";
        } else {
          s.technique = "RDP";
        }
      }

      // Session grouping deferred until after suspicion scoring (see below return block)

      // === Chain Detection: hop-candidate chaining with user continuity + bounded gaps ===
      // Step 1: Build time-windowed hop instances from timeOrdered events
      const _CHAIN_EXCLUDE = /^(127\.\d|::1|0\.0\.0\.0|LOCAL$|-:-$|-$|::1:\d)/i;
      const _hopTech = (evt) => {
        if (["10", "12"].includes(evt.logonType) || ["1149", "21", "22", "24", "25"].includes(evt.eventId)) return "RDP";
        if (evt.logonType === "3" && ["7045", "4697"].includes(evt.eventId)) return "Service Exec";
        if ((evt.eventId === "5140" || evt.eventId === "5145") && evt.shareName) {
          const sn = evt.shareName.replace(/^\\\\\*\\/, "").toUpperCase();
          if (/^(ADMIN\$|C\$|[A-Z]\$)$/.test(sn)) return "Admin Share";
        }
        if (evt.logonType === "9") return "Overpass/PtH"; // NewCredentials — overpass-the-hash / runas /netonly
        if (evt.logonType === "3") return "Network Logon";
        if (evt.logonType === "8") return "Cleartext";
        if (evt.logonType === "2") return "Interactive";
        if (evt.logonType === "13") return "Cached Unlock";
        return null;
      };
      // Surfaced on the result so a capped chain set is visibly capped.
      const chainWarnings = [];
      // Collect all valid hop events, keeping each distinct time instance
      const _hopEvents = [];
      for (const evt of timeOrdered) {
        if (!evt.source || !evt.target || evt.source === evt.target) continue;
        if (_CHAIN_EXCLUDE.test(evt.source) || _CHAIN_EXCLUDE.test(evt.target)) continue;
        if (["4625", "4771", "4776"].includes(evt.eventId)) continue; // skip failures
        const tech = _hopTech(evt);
        if (!tech) continue;
        const user = (evt.user || "").toUpperCase();
        if (!user || user === "-" || user === "ANONYMOUS LOGON" || user === "ANONYMOUS") continue;
        _hopEvents.push({ source: evt.source, target: evt.target, user: evt.user || "(unknown)", ts: evt.ts, technique: tech, eventId: evt.eventId, logonType: evt.logonType, shareName: evt.shareName, evidenceRefs: _dedupeEvidenceRefs(evt.evidenceRefs || []) });
      }
      // Deduplicate within 2-min windows per pair+user (collapse duplicate events, keep distinct instances)
      _hopEvents.sort((a, b) => (a.ts || "").localeCompare(b.ts || ""));
      const HOP_DEDUP_MS = 120000; // 2 min
      const _hops = [];
      const _lastHopTs = new Map(); // "src->tgt|USER" -> lastTs
      for (const evt of _hopEvents) {
        const hk = `${evt.source}->${evt.target}|${evt.user.toUpperCase()}`;
        const lastTs = _lastHopTs.get(hk);
        if (lastTs) {
          const gap = new Date(evt.ts) - new Date(lastTs);
          if (!isNaN(gap) && gap < HOP_DEDUP_MS) continue; // skip near-duplicate
        }
        _lastHopTs.set(hk, evt.ts);
        _hops.push(evt);
      }
      // Hop technique enrichment deferred to after findings (see "Chain Hop Technique Enrichment" block)
      // Build adjacency index: source host -> hops departing from it (sorted by ts)
      const _departFrom = new Map();
      for (const h of _hops) {
        if (!_departFrom.has(h.source)) _departFrom.set(h.source, []);
        _departFrom.get(h.source).push(h);
      }

      // Step 2: Build chains by linking hops with user continuity + bounded gaps
      // Same-user gap: 30 min (no relaxation without session continuity evidence)
      // Different-user gap: 15 min (requires tighter temporal proximity)
      const HOP_GAP_SAME_USER_MS = 1800000; // 30 min
      const HOP_GAP_DIFF_USER_MS = 900000;  // 15 min
      // Chains are capped AFTER dedup and ranking (see below), not while seeding.
      // Seeding used to stop at the first 100 raw chains, and because `_hops` is in
      // ascending time order that meant only the earliest activity ever produced
      // chains — on a busy dataset every later pivot silently yielded none, which also
      // zeroed the Lateral Pivot findings and the chain-membership triage bonus.
      // Seeds are still bounded so a pathological hop count cannot run away.
      const MAX_CHAINS = 500;
      const MAX_CHAIN_SEEDS = 20000;
      const rawChains = [];
      const _seedHops = _hops.length > MAX_CHAIN_SEEDS ? _hops.slice(0, MAX_CHAIN_SEEDS) : _hops;
      if (_hops.length > MAX_CHAIN_SEEDS) {
        chainWarnings.push(`Chain detection considered the first ${MAX_CHAIN_SEEDS.toLocaleString()} of ${_hops.length.toLocaleString()} hops`);
      }

      for (const startHop of _seedHops) {
        const chain = [startHop];
        const visitedHosts = new Set([startHop.source, startHop.target]);
        let currentHop = startHop;
        while (chain.length < 8) {
          const nextHops = _departFrom.get(currentHop.target) || [];
          let bestNext = null;
          let bestGap = Infinity;
          for (const nh of nextHops) {
            if (visitedHosts.has(nh.target)) continue;
            if (!nh.ts || !currentHop.ts) continue;
            const gapMs = new Date(nh.ts) - new Date(currentHop.ts);
            if (gapMs < 0) continue;
            const sameUser = nh.user.toUpperCase() === currentHop.user.toUpperCase();
            const maxGap = sameUser ? HOP_GAP_SAME_USER_MS : HOP_GAP_DIFF_USER_MS;
            if (gapMs > maxGap) continue;
            // Prefer: (1) same user, (2) shortest gap
            const isBetter = !bestNext
              || (sameUser && bestNext.user.toUpperCase() !== currentHop.user.toUpperCase())
              || (sameUser === (bestNext.user.toUpperCase() === currentHop.user.toUpperCase()) && gapMs < bestGap);
            if (isBetter) { bestNext = nh; bestGap = gapMs; }
          }
          if (!bestNext) break;
          chain.push(bestNext);
          visitedHosts.add(bestNext.target);
          currentHop = bestNext;
        }
        if (chain.length >= 2) rawChains.push(chain);
      }

      // Step 3: Deduplicate — group chains by normalized path + user
      const _chainDedup = new Map(); // "path|user" => { chain, occurrences, firstTs, lastTs }
      for (const chain of rawChains) {
        const pathKey = chain.map(h => `${h.source}->${h.target}`).join("|");
        const userKey = chain.map(h => h.user.toUpperCase()).join("|");
        const dk = `${pathKey}::${userKey}`;
        const firstTs = chain[0].ts;
        const lastTs = chain[chain.length - 1].ts;
        if (!_chainDedup.has(dk)) {
          _chainDedup.set(dk, { chain, occurrences: 1, firstTs, lastTs });
        } else {
          const existing = _chainDedup.get(dk);
          existing.occurrences++;
          if (firstTs < existing.firstTs) existing.firstTs = firstTs;
          if (lastTs > existing.lastTs) existing.lastTs = lastTs;
        }
      }

      // Step 4: Build chain objects (confidence scoring deferred until after findings/shared vars)
      // Rank before capping so the cap keeps the longest, most-repeated chains rather
      // than whichever happened to be seeded first.
      const _dedupEntries = [..._chainDedup.values()]
        .sort((a, b) => (b.chain.length - a.chain.length) || (b.occurrences - a.occurrences));
      if (_dedupEntries.length > MAX_CHAINS) {
        chainWarnings.push(`Showing the top ${MAX_CHAINS} of ${_dedupEntries.length.toLocaleString()} distinct chains (longest and most frequent first)`);
      }
      const chains = [];
      for (const entry of _dedupEntries.slice(0, MAX_CHAINS)) {
        const ch = entry.chain;
        const hops = ch.length;
        const path = [ch[0].source, ...ch.map(h => h.target)];
        const hopDetails = ch.map(h => ({
          source: h.source, target: h.target, user: h.user, ts: h.ts,
          technique: h.technique, eventId: h.eventId, logonType: h.logonType,
          evidenceRefs: _dedupeEvidenceRefs(h.evidenceRefs || []),
        }));
        const evidenceRefs = _refsFromEvents(ch);
        const users = [...new Set(ch.map(h => h.user).filter(Boolean))];
        const techniques = [...new Set(ch.map(h => h.technique).filter(Boolean))];
        const timestamps = [ch[0].ts, ...ch.map(h => h.ts)];
        chains.push({
          path, timestamps, users, hops, techniques, hopDetails,
          _rawHops: ch, // kept for deferred confidence scoring
          occurrences: entry.occurrences, firstTs: entry.firstTs, lastTs: entry.lastTs,
          evidenceRefs, itemRowids: _rowidsFromRefs(evidenceRefs),
        });
      }

      // === First-seen Flags ===
      let globalMinTs = null, globalMaxTs = null;
      for (const edge of edgeMap.values()) {
        if (edge.firstSeen) {
          if (!globalMinTs || edge.firstSeen < globalMinTs) globalMinTs = edge.firstSeen;
          if (!globalMaxTs || edge.lastSeen > globalMaxTs) globalMaxTs = edge.lastSeen;
        }
      }
      const totalRangeMs = globalMinTs && globalMaxTs ? (new Date(globalMaxTs) - new Date(globalMinTs)) : 0;
      const firstSeenThresholdTs = totalRangeMs > 0 ? new Date(new Date(globalMinTs).getTime() + totalRangeMs * 0.01).toISOString() : null;
      const firstConnPerSource = new Map();
      for (const edge of edgeMap.values()) {
        const ex = firstConnPerSource.get(edge.source);
        if (!ex || edge.firstSeen < ex) firstConnPerSource.set(edge.source, edge.firstSeen);
      }
      for (const edge of edgeMap.values()) {
        edge.isFirstSeen = (firstSeenThresholdTs && edge.firstSeen <= firstSeenThresholdTs) || firstConnPerSource.get(edge.source) === edge.firstSeen;
      }

      // === Edge Technique Inference + Source Label ===
      // Primary technique = dominant by event count; otherTechniques = supporting list
      const _techPriority = { "Admin Share": 7, "Service Exec": 6, "Overpass/PtH": 6, "Cleartext": 5, "RDP": 4, "Interactive": 3, "Network Logon": 2, "Cached": 1, "Cached Unlock": 1, "Reconnect": 0 };
      for (const edge of edgeMap.values()) {
        const lt = edge.logonTypes; // Set
        const eb = edge.eventBreakdown; // Map
        const techCounts = new Map(); // technique -> event count contributing
        // Admin Share: ADMIN$/C$/[A-Z]$ access via 5140/5145
        if (edge._adminShareCount > 0) {
          techCounts.set("Admin Share", edge._adminShareCount);
        }
        if (lt.has("10") || lt.has("12") || eb.has("1149") || eb.has("21") || eb.has("22")) {
          // Count RDP-specific events + Type 10/12 4624 logons (tracked in edge._rdpLogonCount)
          const rdpSpecific = (eb.get("1149") || 0) + (eb.get("21") || 0) + (eb.get("22") || 0) + (eb.get("24") || 0) + (eb.get("25") || 0);
          techCounts.set("RDP", Math.max(1, rdpSpecific + (edge._rdpLogonCount || 0)));
        }
        if (lt.has("3") && (eb.has("7045") || eb.has("4697"))) {
          techCounts.set("Service Exec", (eb.get("7045") || 0) + (eb.get("4697") || 0));
        } else if (lt.has("3")) {
          // Count type-3 logon events (4624 w/ type 3 approximated by total 4624 minus RDP attribution)
          techCounts.set("Network Logon", (eb.get("4624") || 0));
        }
        if (lt.has("7")) techCounts.set("Reconnect", 1);
        if (lt.has("8")) techCounts.set("Cleartext", (eb.get("4624") || 0));
        if (lt.has("9")) techCounts.set("Overpass/PtH", Math.max(1, eb.get("4624") || 0)); // NewCredentials = runas /netonly / overpass-the-hash
        if (lt.has("11")) techCounts.set("Cached", 1);
        if (lt.has("13")) techCounts.set("Cached Unlock", 1);
        if (lt.has("2")) techCounts.set("Interactive", (eb.get("4624") || 0));
        // Pick primary by count, break ties by priority
        const techArr = [...techCounts.entries()].sort((a, b) => b[1] - a[1] || (_techPriority[b[0]] || 0) - (_techPriority[a[0]] || 0));
        if (techArr.length > 0) {
          edge.technique = techArr[0][0];
          edge.otherTechniques = techArr.slice(1).map(t => t[0]);
        } else {
          edge.technique = "Unknown";
          edge.otherTechniques = [];
        }
        // Source identity label
        const _src = edge.source;
        if (!_src || _src === "-:-" || _src === "::1:0" || _src === "-") edge.sourceLabel = "unresolved";
        else if (/^(127\.|::1|0\.0\.0\.0|LOCAL$)/i.test(_src)) edge.sourceLabel = "loopback";
        else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$/.test(_src) || (_src.includes(":") && !_src.includes("."))) edge.sourceLabel = "IP";
        else edge.sourceLabel = "host";
      }

      // === Attack Pattern Detection ===
      const findings = [];
      let fid = 0;

      // Outlier host detection — flag default/generic/suspicious hostnames
      // Frequency-aware: DESKTOP-*/WIN-* are only outliers if they're a minority (<20%) of hosts.
      // In environments where most workstations have default names, they're the norm, not outliers.
      // Attack tool hostnames (Kali, Parrot, etc.) and generic names are always flagged regardless of frequency.
      const _DEFAULT_WIN_PAT = /^(DESKTOP-[A-Z0-9]{5,}|WIN-[A-Z0-9]{5,})$/;
      const OUTLIER_PATS_ALWAYS = [
        [/^KALI$/i, "Kali Linux default"],
        [/^PARROT$/i, "Parrot OS default"],
        [/^(USER-?PC|YOURNAME|ADMIN|TEST|PC|WIN10|WIN11|OWNER-?PC|USER|WINDOWS|LOCALHOST|HACKER|ATTACKER|ROOT)$/i, "Generic hostname"],
        [/[^\x00-\x7F]/, "Non-ASCII hostname"],
      ];
      const detectOutlier = (hostname) => {
        for (const [pat, reason] of OUTLIER_PATS_ALWAYS) {
          if (pat.test(hostname)) return reason;
        }
        return null;
      };
      const _outlierHosts = new Set();
      // Count DESKTOP-*/WIN-* hosts to determine if they're a minority
      const totalHosts = hostSet.size;
      let defaultWinCount = 0;
      for (const [id] of hostSet) {
        if (_DEFAULT_WIN_PAT.test(id)) defaultWinCount++;
      }
      const defaultWinIsMinority = totalHosts > 0 && (defaultWinCount / totalHosts) < 0.2;
      for (const [id] of hostSet) {
        const alwaysOutlier = detectOutlier(id);
        if (alwaysOutlier) {
          _outlierHosts.add(id);
        } else if (defaultWinIsMinority && _DEFAULT_WIN_PAT.test(id)) {
          // Only flag DESKTOP-*/WIN-* when they're rare in this environment
          _outlierHosts.add(id);
        }
      }

      // === Domain Naming Convention Detection ===
      // Infer the environment's naming convention from the majority of hosts,
      // then flag hosts that don't match as anomalous (possible attacker machines).
      // Also scan the Computer column for hostnames not in the logon graph —
      // machines that logged events but never participated in logon edges.
      let _computerHosts = [];
      if (options._multiSourceComputerHosts) {
        // Multi-source mode: Computer hosts already collected per-tab by multi-source.js
        _computerHosts = options._multiSourceComputerHosts;
      } else if (db && columns.target && meta.colMap[columns.target]) {
        try {
          const _compCol = meta.colMap[columns.target];
          const _compRows = db.prepare(
            `SELECT ${_compCol} as host, COUNT(*) as cnt FROM data WHERE ${_compCol} IS NOT NULL AND ${_compCol} != '' GROUP BY ${_compCol}`
          ).all();
          _computerHosts = _compRows.map(r => ({ host: (r.host || "").toString().trim().toUpperCase(), eventCount: r.cnt })).filter(r => r.host);
        } catch (_e) { /* ignore — Computer column query is best-effort */ }
      }
      const { conventions: _conventions, conventionOutliers: _conventionOutliers } = detectConventions(hostSet, { computerHosts: _computerHosts });
      if (_conventionOutliers.size > 0) {
        // Merge convention outliers into the outlier set so downstream detectors
        // (brute force, operator host, edge scoring) benefit from this signal
        for (const [host] of _conventionOutliers) {
          _outlierHosts.add(host);
        }
      }

      // DC pattern: matches common naming conventions including prefixed/suffixed variants
      // e.g., DC01, PDC-NYC, CORPDC01, AD-PROD-01, ADCS01, DC01-HQ
      // _DC_PAT, _SRV_PAT → ./constants (DC_PAT, SRV_PAT)

      // Brute Force (T1110.001): 5+ failed logons same src->tgt within 5 min
      // Now logon-type-aware: groups failures by pair + logon type family so analysts
      // can distinguish RDP brute force (Type 10) from network (Type 3) from local (Type 2).
      // Type 2 (interactive) where source === target is dampened (password mistype/lockout).
      const _BF_TYPE_LABELS = { "2": "Interactive", "3": "Network", "7": "Unlock", "8": "Cleartext", "10": "RDP", "12": "Cached RDP" };
      const _bfTypeFamily = (lt) => {
        if (lt === "10" || lt === "12") return "rdp";
        if (lt === "3") return "network";
        if (lt === "2") return "interactive";
        if (lt === "8") return "cleartext";
        return "other";
      };
      // SubStatus reason mapping for 4625 failure context
      const _SUBSTATUS_REASONS = {
        "0XC000006A": "bad password", "0XC0000064": "unknown user", "0XC000006D": "bad credentials",
        "0XC0000234": "account locked", "0XC0000072": "account disabled", "0XC000006E": "account restriction",
        "0XC000006F": "outside hours", "0XC0000070": "workstation restriction", "0XC0000071": "password expired",
        "0XC0000193": "account expired", "0XC0000133": "clock skew", "0XC0000224": "must change password",
        "0XC0000413": "auth firewall", "0XC000015B": "logon type denied",
        // Kerberos 4771 failure codes (short hex) — distinct from NT SubStatus codes above
        "0X18": "bad password (Kerberos)", "0X6": "unknown user (Kerberos)", "0X12": "account revoked/disabled/expired",
        "0X17": "password expired (Kerberos)", "0X25": "clock skew (Kerberos)", "0X20": "ticket expired", "0X24": "pre-auth required",
      };
      // Collect failures keyed by pair + logon type family. 4771 (Kerberos pre-auth failure)
      // is the Kerberos equivalent of 4625 and the primary signal for Kerberos brute force /
      // password spray bursts against a DC; it carries no LogonType, so it gets its own family.
      const _bfByPairType = new Map(); // "src->tgt|family" -> {tss[], users, logonTypes, subStatuses}
      for (const evt of timeOrdered) {
        if (evt.eventId !== "4625" && evt.eventId !== "4771") continue;
        const family = evt.eventId === "4771" ? "kerberos" : _bfTypeFamily(evt.logonType);
        const k = `${evt.source}->${evt.target}|${family}`;
        if (!_bfByPairType.has(k)) _bfByPairType.set(k, { tss: [], users: new Set(), logonTypes: new Set(), subStatuses: new Map() });
        const entry = _bfByPairType.get(k);
        entry.tss.push(evt.ts);
        const u = (evt.user || "").trim().toUpperCase();
        if (u) entry.users.add(u);
        if (evt.logonType) entry.logonTypes.add(evt.logonType);
        if (evt.subStatus) entry.subStatuses.set(evt.subStatus.toUpperCase(), (entry.subStatuses.get(evt.subStatus.toUpperCase()) || 0) + 1);
      }
      // SubStatus codes that indicate non-attack failures (dampen severity)
      const _BF_NOISE_SUBSTATUS = new Set(["0XC0000234","0XC0000072","0XC000006E","0XC000006F","0XC0000070","0XC0000071","0XC0000193","0XC0000133","0XC0000224","0XC000015B",
        // Kerberos 4771 benign failure codes: revoked/disabled/expired, password expired, clock skew, ticket expired
        "0X12","0X17","0X25","0X20"]);
      for (const [k, data] of _bfByPairType) {
        const { tss, users, logonTypes, subStatuses } = data;
        if (tss.length < 5) continue;
        tss.sort();
        const [pairPart, family] = k.split("|");
        const [src, tgt] = pairPart.split("->");
        // Dampener: Type 2 (interactive) where source === target is password mistype, not attack
        if (family === "interactive" && src === tgt) continue;
        // SubStatus context: build summary and check if mostly non-attack
        const ssTotal = [...subStatuses.values()].reduce((a, b) => a + b, 0);
        const ssNoiseCount = [...subStatuses.entries()].filter(([code]) => _BF_NOISE_SUBSTATUS.has(code)).reduce((a, [, c]) => a + c, 0);
        const ssMostlyNoise = ssTotal > 0 && (ssNoiseCount / ssTotal) > 0.8;
        const ssLabels = [...subStatuses.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([code, cnt]) => `${_SUBSTATUS_REASONS[code] || code} (${cnt})`);
        const typeLabel = family === "kerberos"
          ? "Kerberos (4771)"
          : ([...logonTypes].map(lt => _BF_TYPE_LABELS[lt] || `Type ${lt}`).join("/") || "Network");
        let _bfBurstCount = 0;
        for (let i = 0; i <= tss.length - 5;) {
          const ws = new Date(tss[i]), we = new Date(tss[i + 4]);
          if (isNaN(ws) || isNaN(we)) { i++; continue; }
          if ((we - ws) <= 300000) {
            let end = i + 4;
            while (end + 1 < tss.length && (new Date(tss[end + 1]) - ws) <= 300000) end++;
            _bfBurstCount++;
            // Severity: RDP/cleartext = high, network = high, interactive = medium
            let severity = "high";
            if (family === "interactive") severity = "medium";
            // Kerberos (4771) without a parsed failure code is lower-confidence — we cannot tell a
            // password-guessing burst from a benign account-lockout/rotation burst, so cap at medium.
            if (family === "kerberos" && ssTotal === 0) severity = "medium";
            // Dampener: >80% of failures are non-attack SubStatus (locked, disabled, expired, etc.)
            if (ssMostlyNoise) {
              if (severity === "high") severity = "medium";
              else if (severity === "medium") severity = "low";
              // A Kerberos burst that is overwhelmingly benign codes (revoked/expired/clock-skew)
              // is account-lockout/rotation noise, not password guessing — fully demote it.
              if (family === "kerberos") severity = "low";
            }
            const _bfPills = [{ text: `${end - i + 1} failures in 5 min`, type: "context" }];
            _bfPills.push({ text: typeLabel, type: "context" });
            if (_bfBurstCount > 1) _bfPills.push({ text: `burst ${_bfBurstCount}`, type: "context" });
            // Add top SubStatus reason as pill for analyst context
            if (ssLabels.length > 0) _bfPills.push({ text: ssLabels[0], type: ssMostlyNoise ? "context" : "credential" });
            if (ssMostlyNoise) _bfPills.push({ text: "non-attack failures (dampened)", type: "context" });
            if (tgt && _DC_PAT.test(tgt)) _bfPills.push({ text: "DC target", type: "target" });
            else if (tgt && _SRV_PAT.test(tgt)) _bfPills.push({ text: "server target", type: "target" });
            if (src && _outlierHosts.has(src)) _bfPills.push({ text: "outlier source", type: "context" });
            const ssDesc = ssLabels.length > 0 ? `. Failure reasons: ${ssLabels.join(", ")}` : "";
            findings.push({ id: fid++, severity, category: "Brute Force", mitre: "T1110.001", title: `Brute force (${typeLabel}): ${src} \u2192 ${tgt}${_bfBurstCount > 1 ? ` (burst ${_bfBurstCount})` : ""}`, description: `${end - i + 1} failed ${typeLabel} logons within 5 minutes${ssDesc}`, source: src, target: tgt, timeRange: { from: tss[i], to: tss[end] }, eventCount: end - i + 1, evidencePills: _bfPills, users: [...users] });
            i = end + 1; // advance past consumed window
          } else {
            i++;
          }
        }
      }

      // Password Spray (T1110.003): same source, same/few users, many distinct targets, failures only
      // Thresholds: 5+ targets = high, 8+ = critical, 3-4 only if source is outlier
      // Dampeners: management sources, service accounts, server targets from known admin nodes
      const _spMgmt = /^(JUMP|JMP|PAM|BASTION|MGMT|MANAGE|SCCM|SCOM|WSUS|MONITOR|NAGIOS|ZABBIX|ANSIBLE|PUPPET|CHEF|SALT|ORCH|NESSUS|QUALYS|QYS|RAPID7|INSIGHTVM|NEXPOSE|TENABLE|OPENVAS|SCANNER|VULNSCAN)[\-_]|^ADMIN[\-_](JUMP|BASTION|PAM|MGMT|SRV|SERVER)/i;
      const _spSvc = /^(SVC[_\-]|SERVICE[_\-]|SYSTEM$|LOCALSERVICE$|NETWORKSERVICE$|HEALTH|MONITOR|SCAN|BACKUP|TASK[_\-]|SCH[_\-]|SA[_\-])/i;
      const _spOutlier = [/^DESKTOP-[A-Z0-9]{5,}$/, /^WIN-[A-Z0-9]{5,}$/, /^KALI$/i, /^PARROT$/i, /^(USER-?PC|YOURNAME|ADMIN|TEST|PC|WIN10|WIN11|OWNER-?PC|USER|WINDOWS|LOCALHOST|HACKER|ATTACKER|ROOT)$/i];
      const _spIsOutlier = (h) => { for (const p of _spOutlier) { if (p.test(h)) return true; } return false; };
      const failedBySrc = new Map();
      for (const evt of timeOrdered) {
        if (evt.eventId !== "4625") continue;
        if (!failedBySrc.has(evt.source)) failedBySrc.set(evt.source, []);
        failedBySrc.get(evt.source).push({ target: evt.target, ts: evt.ts, user: (evt.user || "").trim().toUpperCase() });
      }
      // Also index successful logons per source to detect "no success in window"
      const _spSuccBySrc = new Map();
      for (const evt of timeOrdered) {
        if (evt.eventId !== "4624") continue;
        if (!_spSuccBySrc.has(evt.source)) _spSuccBySrc.set(evt.source, []);
        _spSuccBySrc.get(evt.source).push(evt.ts);
      }
      for (const [src, evts] of failedBySrc) {
        if (evts.length < 3) continue;
        evts.sort((a, b) => (a.ts || "").localeCompare(b.ts || ""));
        const isMgmt = src && _spMgmt.test(src);
        const isOutlier = src && _spIsOutlier(src);
        // Sliding window: find all distinct spray windows (not just first)
        const sprayFindings = [];
        const usedEvts = new Set(); // track consumed event indices to avoid overlapping windows
        for (let i = 0; i < evts.length; i++) {
          if (usedEvts.has(i)) continue;
          const ws = new Date(evts[i].ts);
          if (isNaN(ws)) continue;
          const we = new Date(ws.getTime() + 1800000); // 30-min window
          const tgts = new Set();
          const users = new Set();
          let j = i;
          while (j < evts.length) {
            const t = new Date(evts[j].ts);
            if (isNaN(t) || t > we) break;
            tgts.add(evts[j].target);
            if (evts[j].user) users.add(evts[j].user);
            j++;
          }
          const tgtCount = tgts.size;
          const userCount = users.size;
          // Minimum threshold: 5 targets for standard, 3 for outlier sources
          const minTgt = isOutlier ? 3 : 5;
          if (tgtCount < minTgt) continue;
          // Skip if many distinct users (likely not a spray — more like distributed auth failure)
          if (userCount > 3 && userCount > tgtCount * 0.5) continue;
          // Check for success in window (weakens spray signal)
          const succList = _spSuccBySrc.get(src) || [];
          const hasSuccInWindow = succList.some(st => { const sd = new Date(st); return !isNaN(sd) && sd >= ws && sd <= we; });
          // Base severity from target count
          let severity;
          if (tgtCount >= 8) severity = "critical";
          else if (tgtCount >= 5) severity = "high";
          else severity = "medium"; // 3-4 targets (only reachable for outlier sources)
          // Dampeners
          if (isMgmt) severity = severity === "critical" ? "high" : severity === "high" ? "medium" : "low";
          const allSvc = users.size > 0 && [...users].every(u => _spSvc.test(u) || u.endsWith("$"));
          if (allSvc) severity = severity === "critical" ? "high" : severity === "high" ? "medium" : "low";
          if (hasSuccInWindow && tgtCount < 8) severity = severity === "critical" ? "high" : severity === "high" ? "medium" : severity;
          // Drop if dampened below medium (unless outlier source)
          if (severity === "low" && !isOutlier) continue;
          // Build description
          const desc = [];
          desc.push(`${tgtCount} distinct targets, ${j - i} failures in ${Math.round((new Date(evts[j - 1].ts) - ws) / 60000)} min`);
          if (userCount <= 2) desc.push(`user${userCount > 1 ? "s" : ""}: ${[...users].join(", ")}`);
          else desc.push(`${userCount} distinct users`);
          const ctx = [];
          if (isOutlier) ctx.push("outlier source");
          if (isMgmt) ctx.push("management source (dampened)");
          if (allSvc) ctx.push("service accounts (dampened)");
          if (hasSuccInWindow) ctx.push("success in window");
          sprayFindings.push({
            severity, tgtCount, from: evts[i].ts, to: evts[j - 1].ts, eventCount: j - i,
            targets: [...tgts], users: [...users], description: desc.join("; ") + (ctx.length > 0 ? `. ${ctx.join(", ")}` : ""),
          });
          // Mark events as consumed
          for (let x = i; x < j; x++) usedEvts.add(x);
        }
        for (const sp of sprayFindings) {
          const _spPills = [{ text: `${sp.tgtCount} targets`, type: "context" }];
          if (isOutlier) _spPills.push({ text: "outlier source", type: "context" });
          if (isMgmt) _spPills.push({ text: "management source", type: "context" });
          if (sp.description.includes("service accounts")) _spPills.push({ text: "service accounts", type: "context" });
          if (sp.description.includes("success in window")) _spPills.push({ text: "success in window", type: "credential" });
          findings.push({ id: fid++, severity: sp.severity, category: "Password Spray", mitre: "T1110.003", title: `Password spray from ${src} (${sp.tgtCount} targets)`, description: sp.description, source: src, target: sp.targets.join(", "), timeRange: { from: sp.from, to: sp.to }, eventCount: sp.eventCount, evidencePills: _spPills, users: sp.users });
        }
      }

      // Credential Compromise (T1078): failed then success for SAME USER within 10 min
      // Key by source->target|user to avoid cross-user false positives
      // Clusters repeated fail→success sequences per user per pair
      // FP controls:
      //   - Type 7 (unlock/reconnect) excluded — users unlocking after lockout always produce fail→success
      //   - Type 3 (network) single-failure requires corroborating evidence (stale tickets/NLA retries are common)
      //   - Type 3 single-failure severity capped at medium unless corroborated
      const _ccAnon = /^(-|ANONYMOUS LOGON|ANONYMOUS|DWM-\d|UMFD-\d|SYSTEM|LOCAL SERVICE|NETWORK SERVICE|FONT DRIVER HOST|WINDOW MANAGER)$/i;
      const _ccExcludeLogonTypes = new Set(["7"]); // Type 7 = unlock/reconnect — always noisy
      const _ccEvtsByKey = new Map();
      for (const evt of timeOrdered) {
        if (evt.eventId !== "4625" && evt.eventId !== "4624" && evt.eventId !== "4648") continue;
        // Skip Type 7 events entirely — unlock/reconnect fail→success is not credential compromise
        if (evt.logonType && _ccExcludeLogonTypes.has(evt.logonType)) continue;
        const user = (evt.user || "").trim().toUpperCase();
        if (!user || _ccAnon.test(user)) continue;
        const k = `${evt.source}->${evt.target}|${user}`;
        if (!_ccEvtsByKey.has(k)) _ccEvtsByKey.set(k, []);
        _ccEvtsByKey.get(k).push({ eventId: evt.eventId, ts: evt.ts, user: evt.user, logonType: evt.logonType, source: evt.source, target: evt.target });
      }
      for (const [k, evts] of _ccEvtsByKey) {
        evts.sort((a, b) => (a.ts || "").localeCompare(b.ts || ""));
        // Determine dominant logon type for this key (used for Type 3 dampening)
        const _ccLogonTypes = new Map();
        for (const e of evts) { if (e.logonType) _ccLogonTypes.set(e.logonType, (_ccLogonTypes.get(e.logonType) || 0) + 1); }
        let _ccDominantLT = null, _ccDominantCount = 0;
        for (const [lt, cnt] of _ccLogonTypes) { if (cnt > _ccDominantCount) { _ccDominantLT = lt; _ccDominantCount = cnt; } }
        const isType3 = _ccDominantLT === "3";
        // Type 3 uses tighter 5-min window; others use standard 10-min
        const _ccWindowMs = isType3 ? 300000 : 600000;
        // Collect all fail→success sequences for this user+pair
        const sequences = [];
        const usedSucc = new Set(); // avoid double-counting a success event
        for (let i = 0; i < evts.length; i++) {
          if (evts[i].eventId !== "4625") continue;
          const ft = new Date(evts[i].ts);
          if (isNaN(ft)) continue;
          for (let j = i + 1; j < evts.length; j++) {
            if (evts[j].eventId !== "4624") continue;
            if (usedSucc.has(j)) continue;
            const st = new Date(evts[j].ts);
            if (isNaN(st)) continue;
            const diff = st - ft;
            if (diff > _ccWindowMs) break; // beyond window
            if (diff >= 0) {
              // Context compatibility: check logon type if both present
              const flt = evts[i].logonType, slt = evts[j].logonType;
              if (flt && slt && flt !== slt) continue; // incompatible logon context
              sequences.push({ failTs: evts[i].ts, succTs: evts[j].ts, diffMs: diff, failIdx: i, succIdx: j });
              usedSucc.add(j);
              break; // match this failure to nearest success, move to next failure
            }
          }
        }
        if (sequences.length === 0) continue;
        // Type 3 single-failure gate: require corroborating evidence, otherwise skip entirely.
        // A single network logon fail→success is extremely common (stale Kerberos, NLA retries, multi-DC).
        if (isType3 && sequences.length === 1) {
          const [_t3Src, _t3Rest] = k.split("->");
          const [_t3Tgt] = _t3Rest.split("|");
          const _t3Has4648 = evts.some(e => {
            if (e.eventId !== "4648") return false;
            const et = new Date(e.ts), ft = new Date(sequences[0].failTs), st = new Date(sequences[0].succTs);
            return !isNaN(et) && !isNaN(ft) && !isNaN(st) && et >= new Date(ft.getTime() - 300000) && et <= new Date(st.getTime() + 300000);
          });
          const _t3IsDC = _t3Tgt && _DC_PAT.test(_t3Tgt);
          const _t3IsSrv = _t3Tgt && _SRV_PAT.test(_t3Tgt);
          const _t3IsOutlier = _t3Src && _outlierHosts.has(_t3Src);
          if (!_t3Has4648 && !_t3IsDC && !_t3IsSrv && !_t3IsOutlier) continue;
        }
        const [src, rest] = k.split("->");
        const [tgt] = rest.split("|");
        const user = evts[0].user || "(unknown)";
        // Cluster sequences within 10-min gaps
        const clusters = [];
        let cur = [sequences[0]];
        for (let s = 1; s < sequences.length; s++) {
          const prevEnd = new Date(cur[cur.length - 1].succTs);
          const nextStart = new Date(sequences[s].failTs);
          if (!isNaN(prevEnd) && !isNaN(nextStart) && (nextStart - prevEnd) <= 600000) {
            cur.push(sequences[s]);
          } else {
            clusters.push(cur);
            cur = [sequences[s]];
          }
        }
        clusters.push(cur);
        for (const cluster of clusters) {
          const failCount = cluster.length;
          const fastestDiff = Math.min(...cluster.map(s => s.diffMs));
          const firstFail = cluster[0].failTs;
          const lastSucc = cluster[cluster.length - 1].succTs;
          // Check for explicit creds (4648) within this cluster's time range + 5 min buffer
          const clusterStart = new Date(firstFail);
          const clusterEnd = new Date(lastSucc);
          const has4648 = !isNaN(clusterStart) && !isNaN(clusterEnd) && evts.some(e => {
            if (e.eventId !== "4648") return false;
            const et = new Date(e.ts);
            return !isNaN(et) && et >= new Date(clusterStart.getTime() - 300000) && et <= new Date(clusterEnd.getTime() + 300000);
          });
          // Severity logic:
          //   critical: <=5 min + 4648 explicit creds
          //   high:     default for RDP/interactive or multi-failure clusters
          //   medium:   Type 3 single-failure (passed corroboration gate above but weaker signal)
          let severity = "high";
          if (fastestDiff <= 300000 && has4648) severity = "critical";
          if (isType3 && failCount === 1 && severity !== "critical") {
            severity = (tgt && _DC_PAT.test(tgt)) ? "high" : "medium";
          }
          // Note: post-success tool correlation will be checked after all findings are built
          // (we store the pair key for later cross-referencing in edge scoring)
          const desc = failCount === 1
            ? `Failed logon followed by success within ${Math.round(fastestDiff / 1000)}s`
            : `${failCount} fail\u2192success sequences (fastest: ${Math.round(fastestDiff / 1000)}s)`;
          const ctx = [];
          if (has4648) ctx.push("explicit creds (4648)");
          if (failCount > 3) ctx.push(`${failCount} repeated sequences`);
          if (isType3) ctx.push("network logon (Type 3)");
          const _ccPills = [{ text: "same user fail\u2192success", type: "credential" }];
          if (has4648) _ccPills.push({ text: "4648 explicit creds", type: "credential" });
          if (failCount > 3) _ccPills.push({ text: `${failCount} repeated sequences`, type: "context" });
          if (isType3) _ccPills.push({ text: "Type 3 network", type: "context" });
          if (tgt && _DC_PAT.test(tgt)) _ccPills.push({ text: "DC target", type: "target" });
          else if (tgt && _SRV_PAT.test(tgt)) _ccPills.push({ text: "server target", type: "target" });
          findings.push({ id: fid++, severity, category: "Credential Compromise", mitre: "T1078", title: `Credential compromise: ${user} @ ${src} \u2192 ${tgt}`, description: desc + (ctx.length > 0 ? `. Context: ${ctx.join(", ")}` : ""), source: src, target: tgt, timeRange: { from: firstFail, to: lastSucc }, eventCount: failCount * 2, _ccUser: user, _ccPair: `${src}->${tgt}`, evidencePills: _ccPills, users: [user] });
        }
      }


  return { rdpSessions, chains, findings, fid, _outlierHosts, _computerHosts, _conventionOutliers, detectOutlier, chainWarnings };
}

module.exports = { buildGraphAndChains };
