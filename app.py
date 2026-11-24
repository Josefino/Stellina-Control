#!/usr/bin/env python3
"""Stellina Control — local control app for Vaonis Stellina (version in VERSION below)."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import stellina_auth, stellina_catalog
VERSION='1.9.58'
import uuid
import zipfile, tempfile, shutil
import select, json, socket, ipaddress, time, urllib.request, urllib.error, threading, webbrowser, ftplib, io, posixpath, re, os, base64, hashlib, secrets, struct
from urllib.parse import urlsplit, parse_qs, quote
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

ROOT=Path(__file__).parent
AUTH_LOCK=threading.Lock()
AUTH={'result':'Not requested','challenge_changes':0,'last_challenge_change':None,'verify':None}
IDENTITY={'telescopeId':None,'bootCount':None,'challenge':None}

def local_route(host, port):
    """Which local IP the OS would use to reach host (no packet is sent)."""
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    try:
        s.connect((host,port)); return s.getsockname()[0]
    except OSError as e: return 'NO ROUTE ('+str(e)+')'
    finally: s.close()

def auth_netcheck():
    """TCP connect only to Stellina REST port. No data sent."""
    out={'host':FTP_HOST,'port':8082,'localSource':local_route(FTP_HOST,8082)}
    started=time.monotonic()
    try:
        with socket.create_connection((FTP_HOST,8082),timeout=5): pass
        out.update(ok=True,message='TCP connect OK')
    except OSError as e: out.update(ok=False,message=str(e))
    out['ms']=round((time.monotonic()-started)*1000)
    out['note']='Authorization is computed locally (Ed25519, '+stellina_auth.BACKEND+'); no internet or external server needed.'
    return out

def auth_diagnostics():
    with LIVE_LOCK:
        connected=LIVE['connected']; status=LIVE.get('status') or {}
        owner=status.get('masterDeviceId')
    with AUTH_LOCK:
        identity=dict(IDENTITY); a=dict(AUTH)
    ch=identity['challenge']
    return {'connected':connected,'controlConfirmed':owner==CONTROL_CLIENT,'telescopeIdPresent':bool(identity['telescopeId']),
            'bootCount':identity['bootCount'] if type(identity['bootCount']) is int else None,
            'challengePresent':bool(ch),'challengeLength':len(ch) if isinstance(ch,str) else None,
            'challengeChanges':a['challenge_changes'],'lastChallengeChange':a['last_challenge_change'],
            'lastResult':a['result'],'lastVerify':a['verify'],
            'method':'Local Ed25519 signature (pyvaonis algorithm), backend '+stellina_auth.BACKEND,
            'externalContact':'NONE','initialization':'DISABLED'}

def current_auth_header():
    """Fresh header from the latest challenge. Call right before each REST request."""
    with AUTH_LOCK: identity=dict(IDENTITY)
    if not isinstance(identity['telescopeId'],str) or not identity['telescopeId'] or not isinstance(identity['challenge'],str) or not identity['challenge'] or type(identity['bootCount']) is not int:
        raise ValueError('Missing telescopeId, bootCount or challenge in live telemetry')
    return stellina_auth.build_auth_header(identity['challenge'],identity['telescopeId'],identity['bootCount'])

def request_authorization():
    with LIVE_LOCK:
        if not LIVE['connected'] or not LIVE.get('status'):
            return 409,{'ok':False,'error':'Connect Live first'}
    try: header=current_auth_header()
    except (ValueError,TypeError) as e:
        with AUTH_LOCK: AUTH['result']='Failed: '+str(e)
        return 409,{'ok':False,'error':str(e)}
    with AUTH_LOCK: AUTH['result']='Header computed locally at '+time.strftime('%H:%M:%S')
    return 200,{'ok':True,'headerPrefix':header[:16]+'…','headerLength':len(header),
                'note':'Header is recomputed for every request because the challenge rotates with each status push.',
                'externalContact':'NONE','initialization':'NOT SENT'}

VERIFY_ENDPOINT='/v1/general/stopAutoInit'

def verify_authorization():
    """Auth check on an endpoint that the firmware actually guards.
    general/stopAutoInit is a no-op while no initialization is running (pyvaonis: STATE, reversible).
    Sent three times: no header, header with a deliberately wrong signature, correct header."""
    import http.client
    with LIVE_LOCK:
        st=LIVE.get('status') or {}
        if st.get('masterDeviceId')!=CONTROL_CLIENT:
            return 409,{'ok':False,'error':'Take Control first (the telescope only accepts commands from the master device)'}
        op=st.get('currentOperation')
    if op:
        return 409,{'ok':False,'error':'Telescope reports a running operation; verification refused so nothing gets stopped.','currentOperation':str(op)[:200]}
    def call(mode):
        conn=http.client.HTTPConnection(FTP_HOST,8082,timeout=8)
        try:
            h={'Content-Type':'application/json; charset=UTF-8','Accept':'*/*','Connection':'close'}
            if mode!='none':
                good=current_auth_header()
                if mode=='bad':
                    p,sel,sig=good.split('|'); raw=bytearray(base64.b64decode(sig)); raw[0]^=0xFF
                    good=p+'|'+sel+'|'+base64.b64encode(bytes(raw)).decode()
                h['Authorization']=good
            conn.request('POST',VERIFY_ENDPOINT,body=b'{}',headers=h)
            r=conn.getresponse(); raw=r.read(800).decode('utf-8','replace')
            try: success=json.loads(raw).get('success')
            except (ValueError,AttributeError): success=None
            return {'httpStatus':r.status,'success':success,'preview':raw[:300]}
        except (OSError,ValueError) as e: return {'error':str(e)}
        finally: conn.close()
    res={'noHeader':call('none'),'wrongSignature':call('bad'),'correctHeader':call('good')}
    acc=lambda r:r.get('httpStatus') in range(200,300) and r.get('success') is not False
    denied=lambda r:r.get('httpStatus') in (401,403)
    # Passed auth = anything except 401/403 (e.g. HTTP 500 APP.OPERATION_NOT_FOUND: authorized, nothing to stop)
    passed=lambda r:'httpStatus' in r and not denied(r)
    if passed(res['correctHeader']) and denied(res['wrongSignature']) and denied(res['noHeader']):
        verdict='AUTHORIZATION ACCEPTED (wrong/no header -> 401, correct header passed auth: '+str(res['correctHeader'].get('httpStatus'))+' '+res['correctHeader'].get('preview','')[:80]+')'
    elif acc(res['correctHeader']) and not acc(res['wrongSignature']) and not acc(res['noHeader']):
        verdict='AUTHORIZATION ACCEPTED (correct header accepted, wrong/no header rejected)'
    elif acc(res['correctHeader']) and (acc(res['wrongSignature']) or acc(res['noHeader'])):
        verdict='INCONCLUSIVE: this endpoint also accepts wrong/no header on this firmware'
    elif not any(acc(r) for r in res.values()) and len({(r.get('httpStatus'),r.get('preview')) for r in res.values()})==1:
        verdict='SAME RESPONSE FOR ALL THREE - rejected for a non-auth reason (state/time?); see previews'
    else:
        verdict='CORRECT HEADER REJECTED - see previews'
    with AUTH_LOCK: AUTH['verify']=verdict+' @ '+time.strftime('%H:%M:%S')
    res.update(ok=verdict.startswith('AUTHORIZATION ACCEPTED'),verdict=verdict,endpoint='POST :8082'+VERIFY_ENDPOINT)
    return 200,res

def _busy(st):
    op=st.get('currentOperation')
    return op.get('type') or 'UNKNOWN' if isinstance(op,dict) and not op.get('stopped') else None

def rest_post(path, body, timeout=15):
    """Signed POST to Stellina REST (fresh Authorization header per call)."""
    import http.client
    conn=http.client.HTTPConnection(FTP_HOST,8082,timeout=timeout)
    try:
        raw_body=json.dumps(body,separators=(',',':')).encode()
        conn.request('POST',path,body=raw_body,headers={'Content-Type':'application/json; charset=UTF-8','Accept':'*/*',
                     'Connection':'close','Authorization':current_auth_header()})
        r=conn.getresponse(); raw=r.read(4000).decode('utf-8','replace')
        try: data=json.loads(raw)
        except ValueError: data=None
        return {'httpStatus':r.status,'success':data.get('success') if isinstance(data,dict) else None,'response':data if data is not None else raw[:500]}
    finally: conn.close()

INIT_LOCK=threading.Lock()

def start_autoinit(params):
    """general/startAutoInit exactly as the official app / pyvaonis (AutoInitBody).
    MOVES THE ARM: opens the arm, slews, autofocus, astrometry, starts tracking."""
    global MESSAGE_PENDING
    if not INIT_LOCK.acquire(blocking=False):
        return 409,{'ok':False,'error':'An initialization request is already being sent'}
    try:
        try:
            lat=float(params.get('latitude')); lon=float(params.get('longitude'))
        except (TypeError,ValueError):
            return 400,{'ok':False,'error':'latitude/longitude must be numbers'}
        if not (-90<=lat<=90 and -180<=lon<=180) or (lat==0 and lon==0):
            return 400,{'ok':False,'error':'latitude/longitude out of range'}
        name=str(params.get('observatoryName') or '').strip()[:60] or 'Stellina Control'
        skip_af=bool(params.get('skipAutoFocus',False))
        with LIVE_LOCK:
            st=dict(LIVE.get('status') or {})
            if not LIVE['connected'] or LIVE_SOCKET is None or not st:
                return 409,{'ok':False,'error':'Connect Live and wait for telemetry'}
            try: age=time.time()-time.mktime(time.strptime(LIVE['last_update'],'%Y-%m-%d %H:%M:%S'))
            except (TypeError,ValueError): age=999
            if age>20: return 409,{'ok':False,'error':'Telemetry is stale (%ds); refused'%age}
            if st.get('masterDeviceId')!=CONTROL_CLIENT: return 409,{'ok':False,'error':'Take Control first'}
            if st.get('shuttingDown'): return 409,{'ok':False,'error':'Telescope is shutting down'}
            busy=_busy(st)
            if busy: return 409,{'ok':False,'error':'An operation is already running ('+str(busy)+'); stop it first'}
            # Sync clock first, as the app does on connect (init computes sky positions from it).
            MESSAGE_PENDING='42'+json.dumps(['message','setSystemTime',int(time.time()*1000)],separators=(',',':'))
        time.sleep(1.0)
        body={'latitude':lat,'longitude':lon,'time':int(time.time()*1000),'observatoryId':'','observatoryName':name,'skipAutoFocus':skip_af}
        try: res=rest_post('/v1/general/startAutoInit',body)
        except (OSError,ValueError) as e: return 502,{'ok':False,'error':str(e)}
        trace_live('out','rest','startAutoInit -> HTTP %s'%res['httpStatus'])
        ok=res['httpStatus'] in range(200,300) and res['success'] is not False
        return (200 if ok else 502),{'ok':ok,'sent':body,**res}
    finally: INIT_LOCK.release()

def stop_autoinit():
    with LIVE_LOCK:
        st=dict(LIVE.get('status') or {})
    if st.get('masterDeviceId')!=CONTROL_CLIENT: return 409,{'ok':False,'error':'Take Control first'}
    try: res=rest_post('/v1/general/stopAutoInit',{})
    except (OSError,ValueError) as e: return 502,{'ok':False,'error':str(e)}
    trace_live('out','rest','stopAutoInit -> HTTP %s'%res['httpStatus'])
    return 200,{'ok':res['httpStatus'] in range(200,300),**res}

def userstorage_list(path):
    """List a USB folder. For the root (empty path) the firmware rejects '/', so try the usual
    spellings of the root and return the first one it accepts, with what was tried."""
    p=(path or '').strip()
    if p not in ('','/'): return _userstorage_list_one(p)
    tried=[]
    for cand in ('.','./','','*','root','usb'):
        res=_userstorage_list_one(cand)
        resp=res.get('response') if isinstance(res.get('response'),dict) else {}
        err=(resp.get('error') or {}).get('name') if isinstance(resp.get('error'),dict) else None
        tried.append({'folderPath':cand,'httpStatus':res.get('httpStatus'),'error':err or res.get('error')})
        if res.get('httpStatus')==200 and isinstance(resp.get('result'),dict):
            res['rootPath']=cand; res['triedRoots']=tried; return res
        if err=='STORAGE.NO_USER_STORAGE': res['triedRoots']=tried; return res
    return {'httpStatus':400,'path':'','response':{'error':{'name':'STORAGE.ROOT_NOT_LISTABLE'}},'triedRoots':tried,
            'hint':'The telescope refused every spelling of the USB root. Send this response so we can find the right one.'}

def _userstorage_list_one(path):
    """GET storage/userStorageFolderContent?folderPath=... — lists the USB (user) storage.
    Returns raw JSON so we can learn the schema; expert-mode frames land here, not on the FTP."""
    import http.client
    conn=http.client.HTTPConnection(FTP_HOST,8082,timeout=8)
    try:
        q='/v1/storage/userStorageFolderContent?folderPath='+quote(path,safe='/')
        headers={'Accept':'application/json','Connection':'close'}
        try: headers['Authorization']=current_auth_header()
        except Exception: pass
        conn.request('GET',q,headers=headers)
        r=conn.getresponse(); raw=r.read(60000).decode('utf-8','replace')
        try: data=json.loads(raw)
        except ValueError: data=raw[:2000]
        name=None
        if isinstance(data,dict) and isinstance(data.get('error'),dict): name=data['error'].get('name')
        out={'httpStatus':r.status,'path':path,'response':data}
        if name=='STORAGE.NO_USER_STORAGE': out['hint']='No USB drive detected by the telescope. Insert the drive and wait for the green USB status.'
        return out
    except (OSError,ValueError) as e: return {'error':str(e)}
    finally: conn.close()

def delete_user_folders(folder_paths):
    """POST storage/deleteUserStorageFolders — IRREVERSIBLE. Deletes whole folders from the
    telescope's USER storage only. Guards: requires Take Control, refuses root/system/.. paths,
    and refuses while an operation runs."""
    if not isinstance(folder_paths, list) or not folder_paths:
        return 400,{'ok':False,'error':'No folder selected'}
    clean=[]
    for p in folder_paths:
        if not isinstance(p,str): return 400,{'ok':False,'error':'Bad folder path'}
        if '..' in p.split('/'): return 400,{'ok':False,'error':'Illegal path (..)'}
        # Keep the same relative form the browse endpoint uses (no leading slash).
        norm='/'.join(seg for seg in p.strip().split('/') if seg and seg not in ('.','..'))
        if not norm: return 400,{'ok':False,'error':'Refusing to delete the storage root'}
        if norm.lower()=='system' or norm.lower().startswith('system/'):
            return 403,{'ok':False,'error':'Refusing to touch the system tree (telescope firmware storage)'}
        clean.append(norm)
    with LIVE_LOCK:
        st=dict(LIVE.get('status') or {})
        if not LIVE['connected'] or LIVE_SOCKET is None or not st:
            return 409,{'ok':False,'error':'Connect Live and wait for telemetry'}
        if st.get('masterDeviceId')!=CONTROL_CLIENT: return 409,{'ok':False,'error':'Take Control first'}
        busy=_busy(st)
    if busy in ('OBSERVATION','AUTO_INIT','PLAN','PARK'):
        return 409,{'ok':False,'error':'Refused while '+str(busy)+' is running'}
    try: res=rest_post('/v1/storage/deleteUserStorageFolders',{'folderPaths':clean},timeout=30)
    except (TimeoutError,socket.timeout): return 502,{'ok':False,'error':'timed out'}
    except (OSError,ValueError) as e: return 502,{'ok':False,'error':str(e)}
    trace_live('out','rest','deleteUserStorageFolders %d folder(s) -> HTTP %s'%(len(clean),res['httpStatus']))
    ok=res['httpStatus'] in range(200,300) and res['success'] is not False
    out={'ok':ok,'deleted':clean,**res}
    if not ok: out['hint']=error_hint(res,'HTTP %s — the firmware refused the delete.'%res.get('httpStatus'))
    return (200 if ok else 502),out

def userstorage_download(path, name):
    """Try to fetch a USB file via the :8082/files server under several candidate prefixes.
    Returns {'ok':True,'data':bytes,'name':..,'url':..} or {'ok':False,'tried':[...]}."""
    import http.client
    if not re.match(r'^[A-Za-z0-9._-]{1,64}$', name or ''): raise ValueError('bad filename')
    folder='/'.join(seg for seg in (path or '').strip('/').split('/') if seg and seg not in ('.','..'))
    cands=['/files/'+folder+'/'+name,'/files/user/'+folder+'/'+name,'/files/usb/'+folder+'/'+name,
           '/files/users/'+folder+'/'+name,'/files/user-storage/'+folder+'/'+name]
    tried=[]
    for url in cands:
        try:
            conn=http.client.HTTPConnection(FTP_HOST,8082,timeout=10)
            conn.request('GET',url,headers={'Range':'bytes=0-1','Connection':'close'})
            r=conn.getresponse(); r.read(); st=r.status; conn.close()
            tried.append({'url':url,'status':st})
            if st in (200,206):
                conn=http.client.HTTPConnection(FTP_HOST,8082,timeout=120)
                conn.request('GET',url,headers={'Connection':'close'})
                r=conn.getresponse(); data=r.read(60*1024*1024); conn.close()
                return {'ok':True,'data':data,'name':name,'url':url}
        except OSError as e:
            tried.append({'url':url,'error':str(e)})
    return {'ok':False,'tried':tried,'note':'None of the candidate /files URLs served the file. Send this list so we can find the right path.'}

def _scan_temps(obj, prefix=''):
    found={}
    if isinstance(obj,dict):
        for k,v in obj.items():
            p=prefix+'.'+k if prefix else k
            if isinstance(v,(dict,list)): found.update(_scan_temps(v,p))
            elif isinstance(v,(int,float)) and not isinstance(v,bool) and ('temp' in k.lower() or 'thermal' in k.lower()): found[p]=v
    elif isinstance(obj,list):
        for i,v in enumerate(obj):
            if isinstance(v,(dict,list)): found.update(_scan_temps(v,prefix+'['+str(i)+']'))
    return found

def appstatus_sensors():
    """GET app/status (unauthenticated) for a fresh reading on demand. Also scans the whole
    status for every temperature-like field, to help find one that actually tracks ambient."""
    import http.client
    conn=http.client.HTTPConnection(FTP_HOST,8082,timeout=6)
    try:
        conn.request('GET','/v1/app/status',headers={'Accept':'application/json','Connection':'close'})
        r=conn.getresponse(); raw=r.read(200000)
        if r.status not in range(200,300): return {'ok':False,'httpStatus':r.status,'error':'HTTP %s'%r.status}
        data=json.loads(raw); st=data.get('result') if isinstance(data,dict) else None
        sensors=(st or {}).get('sensors') or {}
        op=(st or {}).get('currentOperation') or {}
        cap=op.get('capture') or {}
        cap_active=bool(op) and not op.get('stopped') and (cap.get('startTemperature') is not None or cap.get('startHumidity') is not None)
        return {'ok':True,'sensors':sensors,'storage':(st or {}).get('storage') or {},'temperatureFields':_scan_temps(st or {}),
                'initialized':(st or {}).get('initialized'),
                'currentOperation':(st or {}).get('currentOperation') is not None,
                'captureTemperature':cap.get('startTemperature'),'captureHumidity':cap.get('startHumidity'),'captureActive':cap_active,
                'time':time.strftime('%H:%M:%S')}
    except (OSError,ValueError,json.JSONDecodeError) as e:
        return {'ok':False,'error':str(e)}
    finally: conn.close()

def _fetch_status_result():
    """GET app/status (unauthenticated) and return the full `result` object, or None.
    Used when we need settings fields that the live worker filters out of LIVE['status']."""
    import http.client
    conn=http.client.HTTPConnection(FTP_HOST,8082,timeout=6)
    try:
        conn.request('GET','/v1/app/status',headers={'Accept':'application/json','Connection':'close'})
        r=conn.getresponse(); raw=r.read(200000)
        if r.status not in range(200,300): return None
        data=json.loads(raw); return data.get('result') if isinstance(data,dict) else None
    except (OSError,ValueError): return None
    finally: conn.close()

_SETTINGS_ECHO_KEYS=('telescopeName','enableLiveFocus','enableFullResolution','enableHdrBackground',
                     'enableDarkUsage','enableDithering','algoHdrBackground','buttonBrightness',
                     'storageFileCategories','usbFileTypes')
def _set_setting(field, value):
    """Change one app/setSettings field, echoing the rest of the current settings."""
    with LIVE_LOCK:
        st=dict(LIVE.get('status') or {})
        if not LIVE['connected'] or LIVE_SOCKET is None or not st:
            return 409,{'ok':False,'error':'Connect Live and wait for telemetry'}
        if st.get('masterDeviceId')!=CONTROL_CLIENT: return 409,{'ok':False,'error':'Take Control first'}
    cur=(_fetch_status_result() or {}).get('settings') or {}
    body={k:cur[k] for k in _SETTINGS_ECHO_KEYS if k in cur}
    body[field]=value
    try: res=rest_post('/v1/app/setSettings',body,timeout=15)
    except (TimeoutError,socket.timeout): return 502,{'ok':False,'error':'timed out'}
    except (OSError,ValueError) as e: return 502,{'ok':False,'error':str(e)}
    ok=res['httpStatus'] in range(200,300) and res['success'] is not False
    out={'ok':ok,field:value,**res}
    if not ok: out['hint']=error_hint(res,'HTTP %s — setSettings refused the change.'%res.get('httpStatus'))
    return (200 if ok else 502),out

def set_live_focus(enabled):
    """enableLiveFocus: the telescope keeps refocusing during an observation (e.g. as temperature drops)."""
    return _set_setting('enableLiveFocus',bool(enabled))

def set_full_resolution(enabled):
    """enableFullResolution (Stellina): stack/export at the sensor's full resolution instead of half."""
    return _set_setting('enableFullResolution',bool(enabled))

LAST_CAPTURE={'id':None,'objectName':None,'stackingCount':None}

def export_tiff():
    """capture/exportImageTiff {captureId}: the telescope renders the current/last stack as a
    full-resolution TIFF and returns its /files URL (plus stackingCount, savedOnUsbStorage)."""
    with LIVE_LOCK:
        st=dict(LIVE.get('status') or {})
        if not LIVE['connected'] or LIVE_SOCKET is None or not st:
            return 409,{'ok':False,'error':'Connect Live and wait for telemetry'}
        if st.get('masterDeviceId')!=CONTROL_CLIENT: return 409,{'ok':False,'error':'Take Control first'}
        cap=((st.get('currentOperation') or {}).get('capture') or {})
        cid=cap.get('id') or LAST_CAPTURE.get('id')
        name=LAST_CAPTURE.get('objectName') or 'stellina'
    if not cid: return 409,{'ok':False,'error':'No capture to export yet — start an observation first (the export uses the stack of the current or last observation in this session)'}
    try: res=rest_post('/v1/capture/exportImageTiff',{'captureId':cid},timeout=180)
    except (TimeoutError,socket.timeout): return 502,{'ok':False,'error':'The telescope did not finish rendering the TIFF within 3 minutes'}
    except (OSError,ValueError) as e: return 502,{'ok':False,'error':str(e)}
    trace_live('out','rest','exportImageTiff %s -> HTTP %s'%(cid,res['httpStatus']))
    resp=res.get('response') if isinstance(res.get('response'),dict) else {}
    result=resp.get('result') if isinstance(resp.get('result'),dict) else {}
    url=result.get('url')
    ok=res['httpStatus'] in range(200,300) and res['success'] is not False and bool(url)
    safe=re.sub(r'[^A-Za-z0-9._-]+','_',str(name)).strip('_') or 'stellina'
    out={'ok':ok,'captureId':cid,'url':url,'stackingCount':result.get('stackingCount'),
         'savedOnUsbStorage':result.get('savedOnUsbStorage'),'filename':safe+'_'+time.strftime('%Y-%m-%d_%H-%M')+'.tif',**res}
    if not ok: out['hint']=error_hint(res,'HTTP %s — the telescope did not return a TIFF.'%res.get('httpStatus') if not url else 'Export failed.')
    return (200 if ok else 502),out

def restart_autofocus(restart_capture=True):
    """general/adjustObservationFocus — the official app's "Restart autofocus" during a deep-sky
    observation. Moves only the focus motor; with restartCapture the stack starts over."""
    with LIVE_LOCK:
        st=dict(LIVE.get('status') or {})
        if not LIVE['connected'] or LIVE_SOCKET is None or not st:
            return 409,{'ok':False,'error':'Connect Live and wait for telemetry'}
        if st.get('masterDeviceId')!=CONTROL_CLIENT: return 409,{'ok':False,'error':'Take Control first'}
        if not _busy(st): return 409,{'ok':False,'error':'No observation running; autofocus runs during an observation (or at initialization)'}
    try: res=rest_post('/v1/general/adjustObservationFocus',{'restartCapture':bool(restart_capture)},timeout=20)
    except (TimeoutError,socket.timeout): return 502,{'ok':False,'error':'timed out'}
    except (OSError,ValueError) as e: return 502,{'ok':False,'error':str(e)}
    trace_live('out','rest','adjustObservationFocus -> HTTP %s'%res['httpStatus'])
    ok=res['httpStatus'] in range(200,300) and res['success'] is not False
    out={'ok':ok,**res}
    if not ok: out['hint']=error_hint(res,'HTTP %s — the telescope refused to refocus.'%res.get('httpStatus'))
    return (200 if ok else 502),out

def set_dark_usage(enabled):
    """Toggle enableDarkUsage via app/setSettings. setSettings echoes the full settings body,
    so we read the current settings and re-send them with just this one field changed."""
    with LIVE_LOCK:
        st=dict(LIVE.get('status') or {})
        if not LIVE['connected'] or LIVE_SOCKET is None or not st:
            return 409,{'ok':False,'error':'Connect Live and wait for telemetry'}
        if st.get('masterDeviceId')!=CONTROL_CLIENT: return 409,{'ok':False,'error':'Take Control first'}
    cur=(_fetch_status_result() or {}).get('settings') or {}
    body={k:cur[k] for k in _SETTINGS_ECHO_KEYS if k in cur}
    body['enableDarkUsage']=bool(enabled)
    try: res=rest_post('/v1/app/setSettings',body,timeout=15)
    except (TimeoutError,socket.timeout): return 502,{'ok':False,'error':'timed out'}
    except (OSError,ValueError) as e: return 502,{'ok':False,'error':str(e)}
    ok=res['httpStatus'] in range(200,300) and res['success'] is not False
    out={'ok':ok,'enableDarkUsage':bool(enabled),**res}
    if not ok: out['hint']=error_hint(res,'HTTP %s — setSettings refused the change.'%res.get('httpStatus'))
    return (200 if ok else 502),out

def firmware_error_name(res):
    r=res.get('response')
    if isinstance(r,dict) and isinstance(r.get('error'),dict): return r['error'].get('name')
    return None

_ERROR_HINTS={
 'EXPERT_MODE.NO_USB_STORAGE_DETECTED':'Expert-mode capture writes to a USB drive, but the Stellina has none plugged in. Insert a USB stick (FAT32/exFAT) into the telescope\'s USB port and retry. Note: the exposure was accepted — this is a storage error, not an exposure limit.',
 'DARK_MANAGER.DUST_FILTER_MISSING':'"Dust filter" is the firmware\'s name for the lens cap — no special accessory is needed. Put the Stellina lens cap on so the telescope detects it (the Filter status on the Dashboard then reads DUST), and retry. Dark generation runs ~30 min in 3 steps (bias/dark/master).',
}
def error_hint(res, fallback):
    name=firmware_error_name(res)
    if name and name in _ERROR_HINTS: return _ERROR_HINTS[name]
    if name: return 'Firmware rejected the command: '+name+'. '+fallback
    return fallback

def _rot(p):
    """Frame rotation (derotator target angle) for manual targets; defaults to 0."""
    r=p.get('rot')
    r=0.0 if r in (None,'') else float(r)
    if not (-360<=r<=360): raise ValueError('Frame rotation must be -360..360 degrees')
    return r

def start_observation(params):
    """general/startObservation. MOVES THE TELESCOPE: slews to the target and images.
    Body is rule-derived (pyvaonis/app) so the firmware accepts it."""
    with LIVE_LOCK:
        st=dict(LIVE.get('status') or {})
        if not LIVE['connected'] or LIVE_SOCKET is None or not st:
            return 409,{'ok':False,'error':'Connect Live and wait for telemetry'}
        try: age=time.time()-time.mktime(time.strptime(LIVE['last_update'],'%Y-%m-%d %H:%M:%S'))
        except (TypeError,ValueError): age=999
        if age>20: return 409,{'ok':False,'error':'Telemetry is stale (%ds); refused'%age}
        if st.get('masterDeviceId')!=CONTROL_CLIENT: return 409,{'ok':False,'error':'Take Control first'}
        if st.get('shuttingDown'): return 409,{'ok':False,'error':'Telescope is shutting down'}
        if not st.get('initialized'): return 409,{'ok':False,'error':'Telescope is not initialized; run Auto-Init first'}
        busy=_busy(st)
        if busy: return 409,{'ok':False,'error':'An operation is already running ('+str(busy)+'); Stop it first'}
    mode=params.get('mode')
    try:
        if mode=='catalog':
            obj=stellina_catalog.get_object(params.get('objectId',''))
            if not obj: return 404,{'ok':False,'error':'Unknown catalog object: '+str(params.get('objectId'))}
            body=stellina_catalog.observation_body(obj)
        elif mode=='manual':
            ra=float(params['ra']); de=float(params['de'])
            if not (0<=ra<360 and -90<=de<=90): return 400,{'ok':False,'error':'RA must be 0-360, Dec -90..90 (degrees)'}
            body=stellina_catalog.manual_body(ra,de,name=str(params.get('name') or '')[:60],
                 gain=params.get('gain') or None,exposure_us=params.get('exposureMicroSec') or None,
                 stacking=bool(params.get('stacking')),rot=_rot(params))
            body=_apply_overrides(body,{'mosaic':params.get('mosaic')},plan=False)
        else:
            return 400,{'ok':False,'error':'mode must be catalog or manual'}
    except (ValueError,KeyError,TypeError) as e:
        return 400,{'ok':False,'error':str(e)}
    try: res=rest_post('/v1/general/startObservation',body)
    except (OSError,ValueError) as e: return 502,{'ok':False,'error':str(e)}
    trace_live('out','rest','startObservation '+str(body.get('objectName') or body.get('ra'))+' -> HTTP %s'%res['httpStatus'])
    ok=res['httpStatus'] in range(200,300) and res['success'] is not False
    out={'ok':ok,'sent':body,**res}
    if not ok:
        out['firmwareError']=firmware_error_name(res)
        out['hint']=error_hint(res,'HTTP %s — the firmware rejected the request (CHECKPARAMS usually means a bad gain/exposure).'%res.get('httpStatus'))
    return (200 if ok else 502),out

def simple_command(path, need_init=False, forbid_busy_types=None, timeout=15, slow=False, slow_note=None):
    with LIVE_LOCK:
        st=dict(LIVE.get('status') or {})
        if not LIVE['connected'] or LIVE_SOCKET is None or not st:
            return 409,{'ok':False,'error':'Connect Live and wait for telemetry'}
        if st.get('masterDeviceId')!=CONTROL_CLIENT: return 409,{'ok':False,'error':'Take Control first'}
        busy=_busy(st)
    if forbid_busy_types and busy in forbid_busy_types:
        return 409,{'ok':False,'error':'Refused while '+busy+' is running'}
    try: res=rest_post(path,{},timeout=timeout)
    except (TimeoutError,socket.timeout):
        if slow:
            trace_live('out','rest',path.rsplit('/',1)[-1]+' (no reply yet; arm moving)')
            return 200,{'ok':True,'inProgress':True,'note':slow_note or 'Command sent. The telescope only replies once the arm has finished moving — watch the Open/Close arm button and the motor telemetry.'}
        return 502,{'ok':False,'error':'timed out'}
    except (OSError,ValueError) as e: return 502,{'ok':False,'error':str(e)}
    trace_live('out','rest',path.rsplit('/',1)[-1]+' -> HTTP %s'%res['httpStatus'])
    return (200 if res['httpStatus'] in range(200,300) else 502),{'ok':res['httpStatus'] in range(200,300),**res}

SINGLE_FRAME_DEG=(1.1,0.7)   # Stellina single frame per Vaonis support: ~1.1 x 0.7 deg
STELLINA_PLAN_MOSAIC_DEG=(1.6,1.1)   # observed: in a PLAN the Stellina firmware always makes a 1.6 x 1.1 deg mosaic
MOSAIC_MAX_AREA_FACTOR=4.0   # Vaonis support: mosaic up to 4x the area of the normal field (direct observations)

def _telescope_model():
    with LIVE_LOCK: m=(LIVE.get('status') or {}).get('model')
    return str(m or 'stellina').lower()

def _apply_overrides(params, it, plan=True):
    """Optional per-target exposure/gain overrides from the sequencer."""
    exp=it.get('exposureMicroSec')
    if exp not in (None,'',0):
        exp=int(exp)
        if not (1000 <= exp <= 600000000): raise ValueError('Target exposure out of range (1 ms – 600 s)')
        params['exposureMicroSec']=exp
    g=it.get('gain')
    if g not in (None,''):
        g=int(g)
        if not (0 <= g <= 10000): raise ValueError('Target gain out of range')
        params['gain']=g
    if it.get('rot') not in (None,'') and 'ra' in params:   # solar targets carry no ra/de/rot
        params['rot']=_rot(it)
    mo=it.get('mosaic')
    if isinstance(mo,dict) and mo.get('width') not in (None,'') and mo.get('height') not in (None,''):
        w=float(mo['width']); h=float(mo['height'])
        fw,fh=SINGLE_FRAME_DEG
        if not (0<w and 0<h): raise ValueError('Field of view must be positive degrees')
        if w>fw+1e-6 or h>fh+1e-6:   # bigger than one frame -> mosaic
            if not params.get('doStacking'): raise ValueError('A larger field of view (mosaic) is only possible for deep-sky (stacked) targets')
            if plan and _telescope_model()=='stellina':
                w,h=STELLINA_PLAN_MOSAIC_DEG   # Stellina firmware builds only this size inside a plan
            else:
                w=max(w,fw); h=max(h,fh); maxa=MOSAIC_MAX_AREA_FACTOR*fw*fh
                if w*h>maxa+1e-6:
                    raise ValueError('Mosaic %.2f° × %.2f° = %.2f deg² is larger than allowed (max 4× the single field = %.2f deg², e.g. 2.2° × 1.4°)'%(w,h,w*h,maxa))
            params['mosaic']={'widthDegree':round(w,3),'heightDegree':round(h,3)}
    return params

def _plan_target_params(it):
    if it.get('objectId'):
        obj=stellina_catalog.get_object(it['objectId'])
        if not obj: raise ValueError('Unknown catalog object: '+str(it['objectId']))
        return _apply_overrides(stellina_catalog.observation_body(obj), it), (obj.get('name') or obj['id'])
    if it.get('ra') is not None and it.get('de') is not None:
        ra=float(it['ra']); de=float(it['de'])
        if not (0<=ra<360 and -90<=de<=90): raise ValueError('RA 0-360, Dec -90..90')
        nm=str(it.get('name') or '')[:60]
        body=stellina_catalog.manual_body(ra,de,name=nm,gain=it.get('gain') or None,
               exposure_us=it.get('exposureMicroSec') or None,stacking=bool(it.get('stacking')),rot=_rot(it))
        return _apply_overrides(body,{'mosaic':it.get('mosaic')}), (nm or f'RA {ra} Dec {de}')
    raise ValueError('Each target needs a catalog objectId or manual ra/de')

def build_plan_payload(items, lat, lon, name, start_ms, observatory_name, device_id):
    if not items: raise ValueError('The plan needs at least one target')
    cursor=int(start_ms); targets=[]; labels=[]
    for it in items:
        minutes=float(it.get('minutes') or 20)
        if not (0 < minutes <= 600): raise ValueError('Each target: minutes must be 1-600')
        params,label=_plan_target_params(it)
        dur=int(minutes*60000)
        targets.append({'startTime':cursor,'endTime':cursor+dur,'params':params})
        labels.append({'label':label,'minutes':minutes})
        cursor+=dur
    return {'planId':str(uuid.uuid4()),'planVersion':str(uuid.uuid4()),'planName':(name or 'Field plan')[:80],
            'targets':targets,'latitude':lat,'longitude':lon,'observatoryId':'',
            'observatoryName':(observatory_name or 'Stellina Control')[:60],'userId':0,
            'deviceId':device_id,'appVersion':'1.38.10'}, labels, cursor

PLAN_END={'action':'none','tiff':False,'armed':False,'seen':False,'idle':0,'userStopped':False,'last':None,'captures':{}}
PLAN_END_ACTIONS=('none','park','shutdown')

def plan_end_public():
    return {**{k:PLAN_END.get(k) for k in ('action','tiff','armed','last')},'capturesSeen':len(PLAN_END.get('captures') or {})}

def _storage_sig():
    with LIVE_LOCK: st=dict(LIVE.get('status') or {})
    s=st.get('storage') or {}
    return tuple((k,(s.get(k) or {}).get('available')) for k in ('data','usb','public','system') if isinstance(s.get(k),dict))

def _wait_storage_quiet(min_s=45,quiet_s=30,max_s=300):
    """Wait at least min_s, then until free space on every telescope storage (internal + USB) has not
    changed for quiet_s seconds, max max_s in total. Returns what was observed."""
    t0=time.time(); last=_storage_sig(); since=time.time(); changes=0
    while True:
        time.sleep(3)
        sig=_storage_sig()
        if sig!=last: last=sig; since=time.time(); changes+=1
        el=time.time()-t0
        if el>=min_s and time.time()-since>=quiet_s: return {'waitedS':round(el),'storageChanges':changes,'quiet':True}
        if el>=max_s: return {'waitedS':round(el),'storageChanges':changes,'quiet':False}

def _is_parked(st):
    """Arm closed/parked. The firmware has no isParked flag in status: like the official app,
    read it from the altitude motor (atStop, or uncalibrated after closing)."""
    if st.get('isParked') is True: return True
    alt=((st.get('motors') or {}).get('ALT') or {}) if isinstance(st.get('motors'),dict) else {}
    return bool(alt.get('atStop')) or alt.get('calibrated') is False

def _op_busy(st):
    op=st.get('currentOperation'); return isinstance(op,dict) and not op.get('stopped')

def _collect_captures(obj,found,depth=0):
    """Find every {capture:{id}} (+ store.storeId, target name) inside a running PLAN/OBSERVATION op."""
    if depth>6: return
    if isinstance(obj,dict):
        cap=obj.get('capture')
        if isinstance(cap,dict) and cap.get('id'):
            store=(obj.get('store') or {}) if isinstance(obj.get('store'),dict) else {}
            tg=(obj.get('target') or {}) if isinstance(obj.get('target'),dict) else {}
            prev=found.get(cap['id'],{})
            found[cap['id']]={'captureId':cap['id'],'storeId':store.get('storeId') or prev.get('storeId'),
                              'objectName':tg.get('objectName') or tg.get('objectId') or prev.get('objectName'),
                              'stackingCount':cap.get('stackingCount',prev.get('stackingCount'))}
        for v in obj.values(): _collect_captures(v,found,depth+1)
    elif isinstance(obj,list):
        for v in obj: _collect_captures(v,found,depth+1)

EXPORT_DIR=ROOT/'exports'

def _http_save(url,dest):
    import http.client
    conn=http.client.HTTPConnection(FTP_HOST,8082,timeout=120)
    try:
        conn.request('GET',url,headers={'Connection':'close'}); r=conn.getresponse()
        if r.status!=200: r.read(); raise OSError('HTTP %s for %s'%(r.status,url))
        n=0; tmp=dest.with_suffix(dest.suffix+'.part')
        with open(tmp,'wb') as f:
            while True:
                ch=r.read(1<<20)
                if not ch: break
                f.write(ch); n+=len(ch)
        tmp.replace(dest); return n
    finally: conn.close()

def _ftp_find_tiffs(store_id):
    """Look for TIFFs the firmware wrote itself under /system/captures/<storeId> (2 levels)."""
    out=[]; base='/system/captures/'+store_id
    def walk(p,d):
        try: ents=list_ftp(p)['entries']
        except Exception: return
        for x in ents:
            q=p.rstrip('/')+'/'+x['name']
            if x['type']=='dir' and d<2: walk(q,d+1)
            elif x['type']=='file' and re.search(r'\.tiff?$',x['name'],re.I): out.append(q)
    walk(base,0); return out

def _save_tiff(c):
    """Save one capture's TIFF to EXPORT_DIR: ask the telescope to render it (exportImageTiff); if that
    is refused for a finished capture, fall back to TIFF files the firmware saved in its library (FTP)."""
    EXPORT_DIR.mkdir(exist_ok=True)
    nm=re.sub(r'[^A-Za-z0-9._-]+','_',str(c.get('objectName') or 'stellina')).strip('_') or 'stellina'
    stamp=time.strftime('%Y-%m-%d_%H-%M')
    try:
        res=rest_post('/v1/capture/exportImageTiff',{'captureId':c['captureId']},timeout=180)
        rr=res.get('response') if isinstance(res.get('response'),dict) else {}
        url=(rr.get('result') or {}).get('url') if isinstance(rr.get('result'),dict) else None
        if res['httpStatus'] in range(200,300) and url:
            dest=EXPORT_DIR/f'{nm}_{stamp}.tif'; n=_http_save(url,dest)
            return {'object':nm,'via':'exportImageTiff','file':str(dest),'bytes':n,'ok':True}
        err='exportImageTiff HTTP %s %s'%(res.get('httpStatus'),firmware_error_name(res) or '')
    except Exception as e: err='exportImageTiff: %s'%e
    if c.get('storeId'):
        try:
            files=_ftp_find_tiffs(c['storeId']); saved=[]
            for p in files:
                data,fn=download_ftp(p); dest=EXPORT_DIR/f'{nm}_{stamp}_{fn}'; dest.write_bytes(data); saved.append(str(dest))
            if saved: return {'object':nm,'via':'ftp','files':saved,'ok':True,'note':err}
            err+='; no TIFF found over FTP in /system/captures/'+c['storeId']
        except Exception as e: err+='; FTP: %s'%e
    return {'object':nm,'ok':False,'error':err}

def _plan_end_run(action,want_tiff,captures):
    """After a plan finished on its own: (park) -> wait until the telescope stopped writing ->
    download TIFFs to this computer -> (shutdown)."""
    log=[]; last={'time':time.strftime('%Y-%m-%d %H:%M:%S'),'action':action,'tiff':want_tiff,'state':'running','steps':log}
    PLAN_END['last']=last
    def phase(t): last['phase']=t
    time.sleep(8)
    with LIVE_LOCK: st=dict(LIVE.get('status') or {})
    parked=_is_parked(st)
    if action in ('park','shutdown'):
        if parked: log.append({'step':'park','skipped':'already parked (the telescope closed itself)'})
        else:
            # The firmware often closes the arm by itself at the end of a plan: give it time first.
            phase('waiting for the telescope to close the arm itself')
            for _ in range(45):
                with LIVE_LOCK: st=dict(LIVE.get('status') or {})
                if _is_parked(st) and not _op_busy(st): parked=True; break
                time.sleep(2)
            if parked: log.append({'step':'park','skipped':'telescope closed the arm itself'})
            else:
                phase('parking')
                code,res=simple_command('/v1/general/park',forbid_busy_types=('OBSERVATION','AUTO_INIT','PLAN'),timeout=120,slow=True)
                log.append({'step':'park','httpStatus':code,'ok':bool(res.get('ok'))}); trace_live('out','plan_end','park -> %s'%code)
                for _ in range(90):
                    with LIVE_LOCK: st=dict(LIVE.get('status') or {})
                    if _is_parked(st) and not _op_busy(st): parked=True; break
                    time.sleep(2)
        log.append({'step':'parked','parked':parked})
    phase('waiting for the telescope to finish saving (TIFF)')
    log.append({'step':'waitSaved',**_wait_storage_quiet(min_s=30,quiet_s=30,max_s=300)})
    if want_tiff:
        phase('downloading TIFF to this computer')
        res=[]
        for c in captures.values():
            r=_save_tiff(c); res.append(r); trace_live('out','plan_end','tiff %s -> %s'%(c.get('objectName'),'ok' if r.get('ok') else r.get('error')))
        if not captures: res.append({'ok':False,'error':'No capture of this plan was seen in telemetry (was the app connected while it ran?)'})
        last['tiffs']=res; log.append({'step':'tiff','saved':sum(1 for r in res if r.get('ok')),'of':len(res)})
    if action=='shutdown':
        if not parked:
            last.update(state='failed',error='Arm is not parked (motors.ALT) — not shutting down for safety.'); return
        phase('shutting down')
        code,res=simple_command('/v1/board/requestShutdown',forbid_busy_types=('OBSERVATION','AUTO_INIT','PLAN','PARK'),timeout=30)
        log.append({'step':'shutdown','httpStatus':code,'ok':bool(res.get('ok'))}); trace_live('out','plan_end','requestShutdown -> %s'%code)
        if not res.get('ok'): last.update(state='failed',error='Shutdown refused: %s'%(res.get('error') or res.get('hint') or code)); return
    last['phase']=None; last['state']='done'

def plan_end_watch(st):
    """Called on every STATUS_UPDATED. Fires the end action once, when a plan we armed ends by itself."""
    if not PLAN_END['armed'] or (PLAN_END['action']=='none' and not PLAN_END.get('tiff')): return
    op=st.get('currentOperation')
    running=isinstance(op,dict) and op.get('type')=='PLAN' and not op.get('stopped')
    if running:
        PLAN_END['seen']=True; PLAN_END['idle']=0
        _collect_captures(op,PLAN_END.setdefault('captures',{}))
        return
    if isinstance(op,dict) and op.get('type')=='OBSERVATION': _collect_captures(op,PLAN_END.setdefault('captures',{}))
    if not PLAN_END['seen']: return
    PLAN_END['idle']+=1
    if PLAN_END['idle']<2: return          # require two consecutive idle updates
    prev=(st.get('previousOperations') or {}).get('plan') if isinstance(st.get('previousOperations'),dict) else None
    stopped_op=op if isinstance(op,dict) and op.get('type')=='PLAN' else prev
    err=((stopped_op or {}).get('error') or {}).get('name') if isinstance((stopped_op or {}).get('error'),dict) else None
    PLAN_END['armed']=False
    if PLAN_END['userStopped'] or err=='OPERATION.USER_INTERRUPTION':
        PLAN_END['last']={'time':time.strftime('%Y-%m-%d %H:%M:%S'),'action':PLAN_END['action'],'state':'skipped','error':'Plan was stopped by the user — no park/shutdown.'}
        return
    threading.Thread(target=_plan_end_run,args=(PLAN_END['action'],bool(PLAN_END.get('tiff')),dict(PLAN_END.get('captures') or {})),daemon=True).start()

def start_plan(params):
    """planner/startPlan — the native 'Plan My Night'. The telescope runs the whole plan itself
    (its own auto-init, target-to-target on schedule) and keeps going after we disconnect."""
    with LIVE_LOCK:
        st=dict(LIVE.get('status') or {})
        if not LIVE['connected'] or LIVE_SOCKET is None or not st:
            return 409,{'ok':False,'error':'Connect Live and wait for telemetry'}
        try: age=time.time()-time.mktime(time.strptime(LIVE['last_update'],'%Y-%m-%d %H:%M:%S'))
        except (TypeError,ValueError): age=999
        if age>20: return 409,{'ok':False,'error':'Telemetry is stale (%ds); refused'%age}
        if st.get('masterDeviceId')!=CONTROL_CLIENT: return 409,{'ok':False,'error':'Take Control first'}
        if st.get('shuttingDown'): return 409,{'ok':False,'error':'Telescope is shutting down'}
        busy=_busy(st)
        if busy: return 409,{'ok':False,'error':'An operation is already running ('+str(busy)+'); stop it first'}
        obs_name=st.get('observatoryName')
    try:
        lat=float(params.get('latitude')); lon=float(params.get('longitude'))
    except (TypeError,ValueError):
        return 400,{'ok':False,'error':'latitude/longitude must be numbers'}
    if not (-90<=lat<=90 and -180<=lon<=180) or (lat==0 and lon==0):
        return 400,{'ok':False,'error':'latitude/longitude out of range'}
    items=params.get('targets')
    if not isinstance(items,list) or not items:
        return 400,{'ok':False,'error':'Add at least one target'}
    start_ms=params.get('startEpochMs')
    if not isinstance(start_ms,(int,float)) or start_ms<=0:
        start_ms=int(time.time()*1000)
    try:
        payload,labels,end_ms=build_plan_payload(items,lat,lon,params.get('planName'),start_ms,
                 params.get('observatoryName') or obs_name, CONTROL_CLIENT)
    except (ValueError,KeyError,TypeError) as e:
        return 400,{'ok':False,'error':str(e)}
    try: res=rest_post('/v1/planner/startPlan',payload)
    except (OSError,ValueError) as e: return 502,{'ok':False,'error':str(e)}
    trace_live('out','rest','startPlan (%d targets) -> HTTP %s'%(len(items),res['httpStatus']))
    ok=res['httpStatus'] in range(200,300) and res['success'] is not False
    ea=str(params.get('endAction') or 'none')
    if ea not in PLAN_END_ACTIONS: ea='none'
    tf=bool(params.get('saveTiff'))
    if ok: PLAN_END.update(action=ea,tiff=tf,armed=(ea!='none' or tf),seen=False,idle=0,userStopped=False,captures={})
    if ok: KEEPAWAKE['until']=max(KEEPAWAKE.get('until',0),end_ms/1000+20*60)
    summary=[]
    for lb,t in zip(labels,payload.get('targets',[])):
        p=t.get('params') or {}; mo=p.get('mosaic') or {}
        summary.append({**lb,'rot':p.get('rot'),'fieldOfView':('%g° × %g° (mosaic)'%(mo['widthDegree'],mo['heightDegree'])) if mo else 'single frame',
                        'exposureMicroSec':p.get('exposureMicroSec'),'gain':p.get('gain')})
    return (200 if ok else 502),{'ok':ok,'targets':summary,
            'startsAt':time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(start_ms/1000)),
            'endsAbout':time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(end_ms/1000)),**res,
            'endAction':ea,'saveTiff':tf,'sent':payload}

def start_darks(params):
    """expertMode/startStorageAcquisition — raw frame stack to disk. No pointing, no init needed
    (lens cap on). Also the safe way to test whether the firmware accepts a given exposure."""
    with LIVE_LOCK:
        st=dict(LIVE.get('status') or {})
        if not LIVE['connected'] or LIVE_SOCKET is None or not st:
            return 409,{'ok':False,'error':'Connect Live and wait for telemetry'}
        try: age=time.time()-time.mktime(time.strptime(LIVE['last_update'],'%Y-%m-%d %H:%M:%S'))
        except (TypeError,ValueError): age=999
        if age>20: return 409,{'ok':False,'error':'Telemetry is stale (%ds); refused'%age}
        if st.get('masterDeviceId')!=CONTROL_CLIENT: return 409,{'ok':False,'error':'Take Control first'}
        if st.get('shuttingDown'): return 409,{'ok':False,'error':'Telescope is shutting down'}
        busy=_busy(st)
        if busy: return 409,{'ok':False,'error':'An operation is already running ('+str(busy)+'); stop it first'}
    try:
        exp=int(params['exposureMicroSec']); gain=int(params.get('gain',200)); num=int(params.get('numExposures',1))
    except (KeyError,TypeError,ValueError):
        return 400,{'ok':False,'error':'exposureMicroSec, gain, numExposures must be integers'}
    if not (1000 <= exp <= 600000000): return 400,{'ok':False,'error':'exposureMicroSec out of range (1 ms – 600 s)'}
    if not (0 <= gain <= 10000): return 400,{'ok':False,'error':'gain out of range'}
    if not (1 <= num <= 200): return 400,{'ok':False,'error':'numExposures must be 1–200'}
    flip=params.get('flip','BOTH')
    if flip not in ('NO_FLIP','FLIP','BOTH'): flip='BOTH'
    # Give each capture its own folder so earlier frames are never overwritten.
    raw_folder=str(params.get('folder') or '').strip()
    folder=re.sub(r'[^A-Za-z0-9_-]+','_',raw_folder)[:40].strip('_')
    if not folder:
        folder='gain%d_%s'%(gain,time.strftime('%Y%m%d_%H%M%S'))
    path='expert-mode/'+folder
    body={'path':path,'overwrite':False,'numExposures':num,'gain':gain,'exposureMicroSec':exp,'flip':flip}
    try: res=rest_post('/v1/expertMode/startStorageAcquisition',body)
    except (OSError,ValueError) as e: return 502,{'ok':False,'error':str(e)}
    trace_live('out','rest','startStorageAcquisition %ss x%d -> HTTP %s'%(exp/1e6,num,res['httpStatus']))
    ok=res['httpStatus'] in range(200,300) and res['success'] is not False
    out={'ok':ok,'sent':body,'savedTo':path,'exposureSeconds':exp/1e6,**res}
    if not ok:
        out['firmwareError']=firmware_error_name(res)
        out['hint']=error_hint(res,'HTTP %s — the firmware rejected the request. If you reused a folder name it may already exist (overwrite is off to protect old frames) — use a new name.'%res.get('httpStatus'))
    return (200 if ok else 502),out

def open_arm():
    """general/openForMaintenance — opens the arm for maintenance. PHYSICAL. Requires Take Control,
    no running operation, and a parked telescope (firmware enforces isParked)."""
    with LIVE_LOCK:
        st=dict(LIVE.get('status') or {})
        if not LIVE['connected'] or LIVE_SOCKET is None or not st:
            return 409,{'ok':False,'error':'Connect Live and wait for telemetry'}
        if st.get('masterDeviceId')!=CONTROL_CLIENT: return 409,{'ok':False,'error':'Take Control first'}
        busy=_busy(st)
        if busy: return 409,{'ok':False,'error':'Refused while '+busy+' is running; stop it first'}
        if st.get('isParked') is False:
            return 409,{'ok':False,'error':'The telescope must be parked first. Park it, then Open arm.'}
    try: res=rest_post('/v1/general/openForMaintenance',{},timeout=90)
    except (TimeoutError,socket.timeout):
        trace_live('out','rest','openForMaintenance (no reply yet; arm moving)')
        return 200,{'ok':True,'inProgress':True,'note':'Command sent. The telescope only replies once the arm has finished moving — watch the Open/Close arm button and the motor telemetry.'}
    except (OSError,ValueError) as e: return 502,{'ok':False,'error':str(e)}
    trace_live('out','rest','openForMaintenance -> HTTP %s'%res['httpStatus'])
    ok=res['httpStatus'] in range(200,300) and res['success'] is not False
    out={'ok':ok,**res}
    if not ok:
        out['firmwareError']=firmware_error_name(res)
        out['hint']=error_hint(res,'If it refused, the telescope probably needs to be parked first (Park, then Open arm).')
    return (200 if ok else 502),out

def motor_registers():
    """debug/motors/readAllStatusRegisters — raw per-motor status registers (positions, flags,
    possibly limit/home switches). Read-only."""
    with LIVE_LOCK:
        st=dict(LIVE.get('status') or {})
        if not LIVE['connected'] or LIVE_SOCKET is None or not st:
            return 409,{'ok':False,'error':'Connect Live and wait for telemetry'}
    try: res=rest_post('/v1/debug/motors/readAllStatusRegisters',{},timeout=10)
    except (OSError,ValueError) as e: return 502,{'ok':False,'error':str(e)}
    trace_live('out','rest','readAllStatusRegisters -> HTTP %s'%res['httpStatus'])
    ok=res['httpStatus'] in range(200,300) and res['success'] is not False
    out={'ok':ok,**res}
    if not ok: out['hint']=error_hint(res,'Reading motor registers may require Take Control.')
    return (200 if ok else 502),out

def set_system_time():
    """Socket.IO 42["message","setSystemTime",<epochMillis>] - what the official app (and pyvaonis) send on connect."""
    global MESSAGE_PENDING
    with LIVE_LOCK:
        if not LIVE['connected'] or LIVE_SOCKET is None:
            return 409,{'ok':False,'error':'Connect Live first'}
        ms=int(time.time()*1000)
        MESSAGE_PENDING='42'+json.dumps(['message','setSystemTime',ms],separators=(',',':'))
    lt=time.localtime(ms/1000)
    return 200,{'ok':True,'queued':'setSystemTime','epochMillis':ms,
                'localTime':time.strftime('%Y-%m-%d %H:%M:%S',lt),
                'timezone':time.strftime('%Z (UTC%z)',lt),
                'utc':time.strftime('%Y-%m-%d %H:%M:%S',time.gmtime(ms/1000)),
                'note':'Sent as an absolute instant (epoch ms) like the official app; the telescope combines it with your latitude/longitude. Shown here in your Mac local time.'}

# STELLINA_BIND=0.0.0.0 lets other devices (e.g. an iPhone on the Pi's hotspot) reach the UI.
HOST=os.environ.get('STELLINA_BIND','127.0.0.1'); PORT=int(os.environ.get('STELLINA_PORT','8766'))

def valid_host(value):
    ip=ipaddress.ip_address(value)
    if not (ip.is_private or ip.is_link_local): raise ValueError('Only private/local IP addresses are permitted')
    return str(ip)

def probe(ip, port, timeout=2):
    started=time.monotonic()
    try:
        with socket.create_connection((ip,port),timeout=timeout): pass
        return {'ok':True,'message':'TCP port reachable','ms':round((time.monotonic()-started)*1000)}
    except OSError as e:
        return {'ok':False,'message':str(e),'ms':round((time.monotonic()-started)*1000)}

def http_probe(ip, port):
    url=f'http://{ip}:{port}/'
    try:
        with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'StellinaControl-Diagnostics/0.1'}),timeout=3) as response:
            body=response.read(1500)
            return {'ok':True,'status':response.status,'content_type':response.headers.get('Content-Type',''),'preview':body.decode('utf-8','replace')}
    except urllib.error.HTTPError as e:
        return {'ok':True,'status':e.code,'content_type':e.headers.get('Content-Type',''),'preview':'Server responded with HTTP error; connection exists.'}
    except Exception as e:
        return {'ok':False,'error':str(e)}

FTP_HOST = '10.0.0.1'
MAX_DOWNLOAD = 1024 * 1024 * 1024  # 1 GiB per file

def safe_ftp_path(path):
    if not isinstance(path, str) or len(path) > 1024 or '\\' in path or '\x00' in path:
        raise ValueError('Invalid FTP path')
    parts = path.split('/')
    if '..' in parts: raise ValueError('Parent traversal is not allowed')
    clean = posixpath.normpath('/' + path.lstrip('/'))
    return clean

FTP_IDLE_SECONDS = 60
FTP_LOCK = threading.RLock()
FTP_SESSION = None
FTP_LAST_USED = 0.0

def close_ftp():
    global FTP_SESSION, FTP_LAST_USED
    with FTP_LOCK:
        old, FTP_SESSION = FTP_SESSION, None
        FTP_LAST_USED = 0.0
        if old is not None:
            try: old.quit()
            except (OSError, EOFError, ftplib.all_errors):
                try: old.close()
                except Exception: pass

def ftp_session():
    global FTP_SESSION, FTP_LAST_USED
    # Caller must hold FTP_LOCK throughout the entire FTP operation.
    if FTP_SESSION is not None and time.monotonic()-FTP_LAST_USED >= FTP_IDLE_SECONDS:
        close_ftp()
    if FTP_SESSION is None:
        ftp=ftplib.FTP()
        try:
            ftp.connect(FTP_HOST, 21, timeout=6)
            ftp.login('anonymous', 'stellina-control@localhost')
            ftp.set_pasv(True)
        except Exception:
            ftp.close()
            raise
        FTP_SESSION=ftp
    FTP_LAST_USED=time.monotonic()
    return FTP_SESSION

def ftp_status():
    with FTP_LOCK:
        return {'connected': FTP_SESSION is not None,
                'idle_seconds': round(time.monotonic()-FTP_LAST_USED) if FTP_SESSION is not None else None,
                'idle_timeout_seconds': FTP_IDLE_SECONDS}

def idle_cleanup():
    while True:
        time.sleep(5)
        with FTP_LOCK:
            if FTP_SESSION is not None and time.monotonic()-FTP_LAST_USED>=FTP_IDLE_SECONDS:
                close_ftp()

def list_ftp(path):
    global FTP_LAST_USED
    path = safe_ftp_path(path)
    with FTP_LOCK:
        ftp=ftp_session()
        try:
            ftp.cwd(path)
            result=[]
            try:
                for name, facts in ftp.mlsd():
                    if name in ('.','..'): continue
                    typ=facts.get('type','unknown')
                    if typ in ('cdir','pdir'): continue
                    result.append({'name':name,'type':'dir' if typ=='dir' else 'file','size':int(facts['size']) if facts.get('size','').isdigit() else None})
            except (ftplib.error_perm, AttributeError):
                for entry in ftp.nlst():
                    name=posixpath.basename(entry.rstrip('/'))
                    if not name or name in ('.','..'):continue
                    isdir=False
                    try:
                        ftp.cwd(name); isdir=True; ftp.cwd(path)
                    except ftplib.error_perm: pass
                    result.append({'name':name,'type':'dir' if isdir else 'file','size':None})
            result.sort(key=lambda x:(x['type']!='dir',x['name'].lower()))
            return {'path':path,'entries':result[:2000],'truncated':len(result)>2000}
        except (OSError,EOFError,ftplib.all_errors):
            close_ftp()
            raise
        finally:
            FTP_LAST_USED=time.monotonic()

def download_ftp(path):
    global FTP_LAST_USED
    path=safe_ftp_path(path)
    if path=='/':raise ValueError('Choose a file')
    with FTP_LOCK:
        ftp=ftp_session()
        try:
            ftp.voidcmd('TYPE I')
            try:
                size=ftp.size(path)
                if size is not None and size>MAX_DOWNLOAD:raise ValueError('File exceeds 1 GiB safety limit')
            except ftplib.error_perm: pass
            buffer=io.BytesIO()
            def add(chunk):
                if buffer.tell()+len(chunk)>MAX_DOWNLOAD:raise ValueError('File exceeds 1 GiB safety limit')
                buffer.write(chunk)
            ftp.retrbinary('RETR '+path,add,blocksize=65536)
            return buffer.getvalue(),posixpath.basename(path)
        except (OSError,EOFError,ftplib.all_errors):
            close_ftp()
            raise
        finally:
            FTP_LAST_USED=time.monotonic()


def save_ftp_files(paths):
    """Save selected FTP files to ~/Downloads, independent of WebKit download support."""
    if not isinstance(paths,list) or not 1<=len(paths)<=500:
        raise ValueError('Select 1–500 files')
    clean=[safe_ftp_path(p) for p in paths]
    if any(p=='/' for p in clean) or len(set(clean))!=len(clean):
        raise ValueError('Invalid or duplicate file selection')
    downloads=Path.home()/'Downloads'
    downloads.mkdir(parents=True,exist_ok=True)
    def unique(name):
        candidate=downloads/name
        i=1
        while candidate.exists():
            candidate=downloads/(f'{Path(name).stem}_{i}{Path(name).suffix}')
            i+=1
        return candidate
    if len(clean)==1:
        path=clean[0]
        name=posixpath.basename(path)
        target=unique(name)
        tmp=None
        try:
            with tempfile.NamedTemporaryFile(dir=downloads,prefix='.stellina_',delete=False) as f:
                tmp=Path(f.name)
                with FTP_LOCK:
                    ftp=ftp_session()
                    total=0
                    def write(chunk):
                        nonlocal total
                        total+=len(chunk)
                        if total>MAX_DOWNLOAD: raise ValueError('File exceeds 1 GiB limit')
                        f.write(chunk)
                    try:
                        ftp.retrbinary('RETR '+path,write,blocksize=262144)
                    except (OSError,EOFError,ftplib.all_errors):
                        close_ftp();raise
            tmp.rename(target)
            return {'ok':True,'files':1,'saved_to':str(target),'bytes':target.stat().st_size}
        finally:
            if tmp is not None: tmp.unlink(missing_ok=True)
    target=unique('Stellina_files.zip')
    tmp=None
    try:
        with tempfile.NamedTemporaryFile(dir=downloads,prefix='.stellina_',delete=False) as f:
            tmp=Path(f.name)
            with zipfile.ZipFile(f,'w',compression=zipfile.ZIP_STORED,allowZip64=True) as z:
                used=set()
                for path in clean:
                    name=posixpath.basename(path)
                    # Avoid collisions from files in different folders.
                    if name in used:
                        name=path.lstrip('/').replace('/','_')
                    if name in used: raise ValueError('Duplicate ZIP entry')
                    used.add(name)
                    with z.open(name,'w',force_zip64=True) as out:
                        with FTP_LOCK:
                            ftp=ftp_session()
                            total=0
                            def write(chunk):
                                nonlocal total
                                total+=len(chunk)
                                if total>MAX_DOWNLOAD: raise ValueError('File exceeds 1 GiB limit')
                                out.write(chunk)
                            try:
                                ftp.retrbinary('RETR '+path,write,blocksize=262144)
                            except (OSError,EOFError,ftplib.all_errors):
                                close_ftp();raise
        tmp.rename(target)
        return {'ok':True,'files':len(clean),'saved_to':str(target),'bytes':target.stat().st_size}
    finally:
        if tmp is not None: tmp.unlink(missing_ok=True)



def save_ftp_folder(folder):
    """Recursively download an FTP directory into a ZIP in ~/Downloads.

    Stream files directly into ZIP (no whole-file buffering), retain subfolders,
    and never modify the remote telescope filesystem.
    """
    global FTP_LAST_USED
    folder=safe_ftp_path(folder)
    if folder=='/':
        raise ValueError('Choose a folder, not the FTP root')
    downloads=Path.home()/'Downloads'
    downloads.mkdir(parents=True,exist_ok=True)
    base=posixpath.basename(folder)
    if base in ('','.','..'):
        raise ValueError('Invalid folder name')
    target=downloads/(base+'.zip')
    suffix=1
    while target.exists():
        target=downloads/(f'{base}_{suffix}.zip')
        suffix+=1
    temp=None
    count=0
    total_bytes=0
    # Limits avoid unbounded traversal from malformed or unexpectedly huge shares.
    max_files=20000
    max_depth=32
    max_total=200*1024**3
    try:
        with tempfile.NamedTemporaryFile(dir=downloads,prefix='.stellina_folder_',delete=False) as f:
            temp=Path(f.name)
            with zipfile.ZipFile(f,'w',compression=zipfile.ZIP_STORED,allowZip64=True) as archive:
                with FTP_LOCK:
                    ftp=ftp_session()
                    def walk(remote,relative,depth):
                        nonlocal count,total_bytes
                        if depth>max_depth:
                            raise ValueError('Folder nesting exceeds 32 levels')
                        ftp.cwd(remote)
                        items=[]
                        try:
                            for name,facts in ftp.mlsd():
                                if name in ('.','..') or facts.get('type') in ('cdir','pdir'):
                                    continue
                                items.append((name,facts.get('type')=='dir'))
                        except (ftplib.error_perm,AttributeError):
                            ftp.cwd(remote)
                            for item in ftp.nlst():
                                name=posixpath.basename(item.rstrip('/'))
                                if name in ('','.','..'):continue
                                is_dir=False
                                try:
                                    ftp.cwd(posixpath.join(remote,name))
                                    is_dir=True
                                except ftplib.error_perm:
                                    pass
                                finally:
                                    ftp.cwd(remote)
                                items.append((name,is_dir))
                        if not items:
                            archive.writestr(relative.rstrip('/')+'/',b'')
                        for name,is_dir in items:
                            if name in ('.','..') or '/' in name or '\\' in name or '\x00' in name:
                                raise ValueError('Unsafe FTP entry name')
                            remote_child=safe_ftp_path(posixpath.join(remote,name))
                            zip_child=relative+'/'+name
                            if is_dir:
                                archive.writestr(zip_child+'/',b'')
                                walk(remote_child,zip_child,depth+1)
                            else:
                                if count>=max_files:
                                    raise ValueError('Folder contains more than 20,000 files')
                                count+=1
                                file_bytes=0
                                with archive.open(zip_child,'w',force_zip64=True) as dest:
                                    def write(chunk):
                                        nonlocal file_bytes,total_bytes
                                        file_bytes+=len(chunk)
                                        total_bytes+=len(chunk)
                                        if file_bytes>MAX_DOWNLOAD:
                                            raise ValueError('File exceeds 1 GiB limit: '+remote_child)
                                        if total_bytes>max_total:
                                            raise ValueError('Folder exceeds 200 GiB total limit')
                                        dest.write(chunk)
                                    ftp.retrbinary('RETR '+remote_child,write,blocksize=262144)
                                ftp.cwd(remote)
                    try:
                        walk(folder,base,0)
                    except (OSError,EOFError,ftplib.all_errors):
                        close_ftp()
                        raise
                    finally:
                        FTP_LAST_USED=time.monotonic()
        temp.rename(target)
        return {'ok':True,'files':count,'saved_to':str(target),'bytes':target.stat().st_size,'folder':folder}
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


# Telescope service diagnostics based on jrrk2/openstellina telescope.ml:
# pth2'=8082, pth3'=8083, Socket.IO v3 at /socket.io/?EIO=3&transport=polling
# No Socket.IO events or telescope commands are transmitted.
TELESCOPE_PORTS=(8082,8083)
def telescope_probe():
    return {'ip':FTP_HOST,'ports':{str(p):probe(FTP_HOST,p,timeout=1.5) for p in TELESCOPE_PORTS},
            'source':'OpenStellina telescope.ml (ports 8082 and 8083)',
            'timestamp':time.strftime('%Y-%m-%d %H:%M:%S')}

def socketio_handshake():
    # Explicit, one-shot GET only. This may allocate a temporary server-side
    # Socket.IO session; no control request, event, upgrade, or loop follows.
    url=f'http://{FTP_HOST}:8083/socket.io/?EIO=3&transport=polling&id=stellina-control-diagnostics&name=stellina-control-diagnostics'
    started=time.monotonic()
    try:
        req=urllib.request.Request(url,headers={'User-Agent':'StellinaControl/0.6 (read-only diagnostic)','Accept':'*/*'})
        with urllib.request.urlopen(req,timeout=3) as response:
            body=response.read(4096).decode('utf-8','replace')
            result={'ok':True,'status':response.status,'content_type':response.headers.get('Content-Type',''),
                    'body_preview':body[:1500]}
            # Engine.IO v3 polling handshake normally contains 0{...}.
            idx=body.find('0{')
            if idx>=0:
                try:
                    decoder=json.JSONDecoder()
                    data,_=decoder.raw_decode(body[idx+1:])
                    result['handshake']={'sid_present':bool(data.get('sid')),
                      'upgrades':data.get('upgrades'), 'pingInterval':data.get('pingInterval'),
                      'pingTimeout':data.get('pingTimeout')}
                except (ValueError,TypeError):pass
    except urllib.error.HTTPError as e:
        result={'ok':False,'status':e.code,'error':f'HTTP {e.code} {e.reason}'}
    except (OSError,ValueError) as e:
        result={'ok':False,'error':str(e)}
    result['elapsed_ms']=round((time.monotonic()-started)*1000)
    result['note']='One-shot read-only Engine.IO handshake. No telescope commands sent.'
    return result


# WebSocket diagnostic: standard-library-only RFC 6455 client. Passive application
# behavior: no Socket.IO 40 namespace connect, events, control, or motor commands.
# RFC-required WebSocket control frames and Engine.IO ping responses are permitted.
WS_DIAG_LOCK = threading.Lock()
WS_MAX_PAYLOAD = 65536

def ws_send(sock, opcode, payload=b''):
    if isinstance(payload,str): payload=payload.encode('utf-8')
    mask=secrets.token_bytes(4)
    length=len(payload)
    header=bytes([0x80 | opcode])
    if length<126: header+=bytes([0x80 | length])
    elif length<=65535: header+=bytes([0x80 | 126])+struct.pack('!H',length)
    else: header+=bytes([0x80 | 127])+struct.pack('!Q',length)
    sock.sendall(header+mask+bytes(b ^ mask[i%4] for i,b in enumerate(payload)))

def ws_read_exact(sock,n):
    buf=bytearray()
    while len(buf)<n:
        chunk=sock.recv(n-len(buf))
        if not chunk:raise EOFError('WebSocket connection closed')
        buf.extend(chunk)
    return bytes(buf)

def ws_read_frame(sock):
    head=ws_read_exact(sock,2)
    fin=bool(head[0]&128); opcode=head[0]&15
    masked=bool(head[1]&128); length=head[1]&127
    if length==126:length=struct.unpack('!H',ws_read_exact(sock,2))[0]
    elif length==127:length=struct.unpack('!Q',ws_read_exact(sock,8))[0]
    if length>WS_MAX_PAYLOAD:raise ValueError('WebSocket frame exceeds diagnostic size limit')
    mask=ws_read_exact(sock,4) if masked else None
    data=ws_read_exact(sock,length)
    if mask:data=bytes(b ^ mask[i%4] for i,b in enumerate(data))
    return fin,opcode,data

def ws_pop_frame(buffer):
    """Incremental WebSocket frame parser: preserves partial frames across polls."""
    if len(buffer) < 2:
        return None
    b0, b1 = buffer[0], buffer[1]
    length = b1 & 127
    offset = 2
    if length == 126:
        if len(buffer) < 4: return None
        length = struct.unpack('!H', buffer[2:4])[0]
        offset = 4
    elif length == 127:
        if len(buffer) < 10: return None
        length = struct.unpack('!Q', buffer[2:10])[0]
        offset = 10
    if length > WS_MAX_PAYLOAD:
        raise ValueError('WebSocket frame exceeds maximum size')
    masked = bool(b1 & 128)
    needed = offset + (4 if masked else 0) + length
    if len(buffer) < needed:
        return None
    if masked:
        mask = buffer[offset:offset+4]
        offset += 4
    payload = bytes(buffer[offset:offset+length])
    if masked:
        payload = bytes(c ^ mask[i%4] for i,c in enumerate(payload))
    del buffer[:needed]
    return bool(b0 & 128), b0 & 15, payload

def websocket_diagnostic(duration=12):
    if not WS_DIAG_LOCK.acquire(blocking=False):
        return {'ok':False,'error':'A WebSocket diagnostic is already running'}
    sock=None; started=time.monotonic()
    result={'ok':False,'ip':FTP_HOST,'port':8083,'duration_limit_s':duration,
            'mode':'Passive WebSocket / Engine.IO 3; no telescope commands',
            'frames':[],'websocket_upgrade':False,'engineio_handshake':None}
    try:
        sock=socket.create_connection((FTP_HOST,8083),timeout=3)
        sock.settimeout(3)
        key=base64.b64encode(secrets.token_bytes(16)).decode('ascii')
        path='/socket.io/?EIO=3&transport=websocket&id=stellina-control-diagnostics&name=stellina-control-diagnostics'
        request=(f'GET {path} HTTP/1.1\r\nHost: {FTP_HOST}:8083\r\nUpgrade: websocket\r\n'
                 f'Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n'
                 f'User-Agent: StellinaControl/0.7\r\n\r\n')
        sock.sendall(request.encode('ascii'))
        header=b''
        while b'\r\n\r\n' not in header:
            piece=sock.recv(1)
            if not piece:raise EOFError('Connection closed during HTTP upgrade')
            header+=piece
            if len(header)>8192:raise ValueError('Oversized HTTP upgrade headers')
        lines=header.decode('latin-1').split('\r\n')
        result['http_status']=lines[0]
        if not lines[0].startswith('HTTP/1.1 101 '):raise ValueError('WebSocket upgrade rejected: '+lines[0])
        headers={k.strip().lower():v.strip() for line in lines[1:] if ':' in line for k,v in [line.split(':',1)]}
        expected=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode('ascii')).digest()).decode('ascii')
        if headers.get('sec-websocket-accept')!=expected:raise ValueError('Invalid Sec-WebSocket-Accept')
        result['websocket_upgrade']=True
        deadline=time.monotonic()+duration
        while time.monotonic()<deadline and len(result['frames'])<30:
            sock.settimeout(min(2,max(.1,deadline-time.monotonic())))
            try:fin,opcode,data=ws_read_frame(sock)
            except socket.timeout:continue
            if opcode==8:
                result['frames'].append({'kind':'websocket_close','code':struct.unpack('!H',data[:2])[0] if len(data)>=2 else None})
                break
            if opcode==9:
                ws_send(sock,10,data)
                result['frames'].append({'kind':'websocket_ping','response':'pong'})
                continue
            if opcode==10:
                result['frames'].append({'kind':'websocket_pong'})
                continue
            if opcode!=1:
                result['frames'].append({'kind':'non_text_frame','opcode':opcode,'bytes':len(data),'fin':fin})
                continue
            msg=data.decode('utf-8','replace')
            item={'kind':'text','bytes':len(data),'preview':msg[:1500]}
            if msg.startswith('0{'):
                try:
                    handshake=json.loads(msg[1:])
                    result['engineio_handshake']={'sid_present':bool(handshake.get('sid')),
                        'upgrades':handshake.get('upgrades'), 'pingInterval':handshake.get('pingInterval'),
                        'pingTimeout':handshake.get('pingTimeout')}
                    item['kind']='engineio_open'
                    item.pop('preview',None) # do not expose session identifiers
                except (ValueError,TypeError):pass
            elif msg=='2':
                ws_send(sock,1,'3')
                item['kind']='engineio_ping';item['response']='engineio_pong'
            elif msg.startswith('42'):
                item['kind']='socketio_event'
            result['frames'].append(item)
        result['ok']=True
    except (OSError,EOFError,ValueError) as exc:
        result['error']=f'{type(exc).__name__}: {exc}'
    finally:
        if sock is not None:
            try:
                if result['websocket_upgrade']:ws_send(sock,8,struct.pack('!H',1000))
            except (OSError,ValueError):pass
            try:sock.close()
            except OSError:pass
        result['elapsed_ms']=round((time.monotonic()-started)*1000)
        result['closed']=True
        WS_DIAG_LOCK.release()
    return result


# Persistent read-only WebSocket telemetry. A single backend connection is shared
# by all browser tabs. No telescope application commands are transmitted.
LIVE_LOCK=threading.RLock()
LIVE={'connected':False,'connecting':False,'last_update':None,'last_error':None,
      'status':None,'events':0,'started':None,'protocol':'Engine.IO 3 / Socket.IO','control_state':'Not requested','control_message':None,'control_requested_at':None,'disconnect_reason':None,'ping_received':0,'pong_sent':0,'ws_ping_received':0,'ws_pong_sent':0,'last_ping':None,'last_pong':None,'last_frame':None,'close_code':None,'trace':[],'namespace_connected':False,'last_engine_frame':None,'connected_at':None,'probe_sent':0,'probe_received':0,'last_probe_sent':None,'last_probe_reply':None}
LIVE_THREAD=None
LIVE_STOP=threading.Event()
LIVE_SOCKET=None
CONTROL_PENDING=None
MESSAGE_PENDING=None  # raw Socket.IO frame, e.g. setSystemTime
CONTROL_CLIENT='stellina-control-live'

def live_snapshot(touch=True):
    with LIVE_LOCK:
        return dict(LIVE)

def trace_live(direction, kind, detail=''):
    # Bounded protocol trace: never record raw STATUS_UPDATED payloads, challenge, or session IDs.
    item={'time':time.strftime('%Y-%m-%d %H:%M:%S'), 'direction':direction,
          'kind':kind, 'detail':str(detail)[:180]}
    with LIVE_LOCK:
        LIVE['trace'].append(item)
        del LIVE['trace'][:-100]

def live_worker():
    global LIVE_SOCKET,CONTROL_PENDING
    sock=None
    reason="Connection ended"
    auto_time_sent=False
    try:
        sock=socket.create_connection((FTP_HOST,8083),timeout=4)
        sock.settimeout(3)
        with LIVE_LOCK: LIVE_SOCKET=sock
        key=base64.b64encode(secrets.token_bytes(16)).decode('ascii')
        path='/socket.io/?EIO=3&transport=websocket&id=stellina-control-live&name=stellina-control-live'
        req=(f'GET {path} HTTP/1.1\r\nHost: {FTP_HOST}:8083\r\nUpgrade: websocket\r\n'
             f'Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n'
             'User-Agent: StellinaControl/0.9.4\r\n\r\n')
        sock.sendall(req.encode('ascii'))
        header=b''
        while b'\r\n\r\n' not in header:
            part=sock.recv(1)
            if not part:raise EOFError('WebSocket upgrade closed')
            header+=part
            if len(header)>8192:raise ValueError('WebSocket headers too large')
        if not header.startswith(b'HTTP/1.1 101 '):raise ValueError('WebSocket upgrade rejected')
        h={k.strip().lower():v.strip() for line in header.decode('latin-1').split('\r\n')[1:] if ':' in line for k,v in [line.split(':',1)]}
        expected=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        if h.get('sec-websocket-accept')!=expected:raise ValueError('Invalid WebSocket accept header')
        with LIVE_LOCK:LIVE.update(connected=True,connecting=False,connected_at=time.strftime('%Y-%m-%d %H:%M:%S'))
        trace_live('in','http_upgrade','HTTP 101; WebSocket handshake verified')
        incoming=bytearray()
        # OpenStellina sends an Engine.IO '2probe' every 25 seconds.
        # Send slightly before the observed 30-second server timeout.
        next_probe=time.monotonic()+20.0
        while not LIVE_STOP.is_set():
            with LIVE_LOCK:
                if LIVE['control_state'] in ('Request pending','Release pending') and LIVE['control_requested_at']:
                    try: expired=time.time()-time.mktime(time.strptime(LIVE['control_requested_at'],'%Y-%m-%d %H:%M:%S'))>15
                    except ValueError: expired=False
                    if expired:
                        LIVE['control_state']='Unconfirmed (timeout)'
                        LIVE['control_message']='No ownership confirmation within 15 seconds; check masterDeviceId'
            # All application writes occur in this one WebSocket worker thread.
            with LIVE_LOCK:
                command=CONTROL_PENDING
                CONTROL_PENDING=None
            with LIVE_LOCK:
                raw_msg=MESSAGE_PENDING
                globals()['MESSAGE_PENDING']=None
            if raw_msg:
                ws_send(sock,1,raw_msg)
                trace_live('out','socketio_message',raw_msg[:120])
            if command:
                ws_send(sock,1,'42["message","'+command+'"]')
                trace_live('out','socketio_command',command)
                with LIVE_LOCK:
                    LIVE['control_message']='Sent '+command+'; waiting for telescope confirmation'
                    LIVE['control_requested_at']=time.strftime('%Y-%m-%d %H:%M:%S')

            # Experimental keepalive matching the upstream OpenStellina implementation.
            # This is a protocol probe, NOT a telescope movement/control command.
            if time.monotonic() >= next_probe:
                ws_send(sock,1,'2probe')
                now=time.strftime('%Y-%m-%d %H:%M:%S')
                with LIVE_LOCK: LIVE.update(probe_sent=LIVE['probe_sent']+1,last_probe_sent=now)
                trace_live('out','engine_probe','2probe (upstream OpenStellina keepalive)')
                next_probe=time.monotonic()+20.0

            # Wait for network data without losing partially received frames.
            readable,_,_=select.select([sock],[],[],0.25)
            if readable:
                chunk=sock.recv(65536)
                if not chunk:raise EOFError('Remote TCP connection closed')
                incoming.extend(chunk)
                if len(incoming)>WS_MAX_PAYLOAD+32:
                    raise ValueError('WebSocket receive buffer limit exceeded')
            while True:
                frame=ws_pop_frame(incoming)
                if frame is None:break
                fin,opcode,data=frame
                with LIVE_LOCK:LIVE['last_frame']=time.strftime('%Y-%m-%d %H:%M:%S')
                if opcode==8:
                    code=struct.unpack('!H',data[:2])[0] if len(data)>=2 else None
                    with LIVE_LOCK:LIVE['close_code']=code
                    reason=f'Remote WebSocket close frame (code {code})'
                    trace_live('in','websocket_close',f'code={code}; reason={data[2:].decode("utf-8","replace")[:90] if len(data)>2 else "none"}')
                    break
                if opcode==9:
                    trace_live('in','ws_ping',f'bytes={len(data)}')
                    ws_send(sock,10,data)
                    with LIVE_LOCK:LIVE.update(ws_ping_received=LIVE['ws_ping_received']+1,ws_pong_sent=LIVE['ws_pong_sent']+1)
                    trace_live('out','ws_pong',f'bytes={len(data)}')
                    continue
                if opcode==10:
                    trace_live('in','ws_pong',f'bytes={len(data)}')
                    continue
                if opcode!=1 or not fin:
                    trace_live('in','ws_frame',f'opcode={opcode}, fin={fin}, bytes={len(data)}')
                    continue
                msg=data.decode('utf-8','replace')
                if msg=='2':
                    trace_live('in','engine_ping','2')
                    with LIVE_LOCK:LIVE.update(ping_received=LIVE['ping_received']+1,last_ping=time.strftime('%Y-%m-%d %H:%M:%S'))
                    ws_send(sock,1,'3')
                    trace_live('out','engine_pong','3')
                    with LIVE_LOCK:LIVE.update(pong_sent=LIVE['pong_sent']+1,last_pong=time.strftime('%Y-%m-%d %H:%M:%S'))
                    continue
                if msg.startswith('0'):
                    try:
                        handshake=json.loads(msg[1:])
                        trace_live('in','engine_open',f'pingInterval={handshake.get("pingInterval")}, pingTimeout={handshake.get("pingTimeout")}')
                    except (ValueError,TypeError):trace_live('in','engine_open','malformed')
                    continue
                if msg=='40':
                    with LIVE_LOCK:LIVE['namespace_connected']=True
                    trace_live('in','socketio_namespace_connected','40 (server acknowledged)')
                    continue
                if msg=='3probe':
                    with LIVE_LOCK: LIVE.update(probe_received=LIVE['probe_received']+1,last_probe_reply=time.strftime('%Y-%m-%d %H:%M:%S'))
                    trace_live('in','engine_probe_reply','3probe')
                    continue
                if msg=='3':
                    trace_live('in','engine_pong','3')
                    continue
                if msg.startswith('42'):
                    try:
                        event=json.loads(msg[2:])
                        if isinstance(event,list) and len(event)>1 and event[0]=='STATUS_UPDATED' and isinstance(event[1],dict):
                            st=event[1]
                            trace_live('in','socketio_event','STATUS_UPDATED (payload redacted)')
                            # Only expose known telemetry fields. Never expose challenge or session IDs.
                            keep=('apiVersion','version','telescopeId','model','initialized','shuttingDown','bootCount','sensors','motors','filter','network','settings','storage','masterDeviceId','currentOperation','otherCurrentOperations','elapsedTime','position','observatoryName','isParked')
                            clean={k:st[k] for k in keep if k in st}
                            try: plan_end_watch(st)
                            except Exception as _e: trace_live('in','plan_end','watch error %s'%_e)
                            clean['planEndAction']=plan_end_public()
                            try:
                                _cap=(st.get('currentOperation') or {}).get('capture') or {}
                                if _cap.get('id'):
                                    LAST_CAPTURE.update(id=_cap['id'],objectName=((_cap.get('target') or {}).get('objectName') or ((st.get('currentOperation') or {}).get('target') or {}).get('objectName')),stackingCount=_cap.get('stackingCount'))
                            except (AttributeError,TypeError): pass
                            prev_ai=(st.get('previousOperations') or {}).get('autoInit') if isinstance(st.get('previousOperations'),dict) else None
                            if isinstance(prev_ai,dict):
                                clean['lastAutoInit']={k:prev_ai.get(k) for k in ('id','startTime','endTime','stopped','error','observatoryName','astrometry')}
                            if 'settings' in clean:clean['settings']={k:v for k,v in clean['settings'].items() if k in ('telescopeName','enableDithering','enableFullResolution','enableLiveFocus','band','enableDarkUsage')}
                            # Store challenge only in backend memory; never expose it in status or trace.
                            identity={k:st.get(k) for k in ('telescopeId','bootCount','challenge')}
                            with AUTH_LOCK:
                                if any(IDENTITY.get(k)!=identity[k] for k in identity):
                                    if IDENTITY.get('challenge') is not None:
                                        AUTH['challenge_changes']+=1
                                        AUTH['last_challenge_change']=time.strftime('%Y-%m-%d %H:%M:%S')
                                    IDENTITY.update(identity)
                            with LIVE_LOCK:
                                master=clean.get('masterDeviceId')
                                if master==CONTROL_CLIENT:state='Control granted (confirmed by telemetry)'
                                elif master:state='Controlled by another device'
                                elif LIVE['control_state'] in ('Request pending','Release pending'):state=LIVE['control_state']
                                else:state='No control owner'
                                LIVE.update(status=clean,last_update=time.strftime('%Y-%m-%d %H:%M:%S'),events=LIVE['events']+1,control_state=state)
                            if not auto_time_sent:
                                # Stellina has no battery-backed real-time clock, so sync it from this
                                # computer automatically once telemetry is flowing (as the official app does).
                                ms=int(time.time()*1000)
                                ws_send(sock,1,'42'+json.dumps(['message','setSystemTime',ms],separators=(',',':')))
                                auto_time_sent=True
                                now=time.strftime('%Y-%m-%d %H:%M:%S')
                                with LIVE_LOCK: LIVE['clock_synced']=now
                                trace_live('out','socketio_message','setSystemTime (auto on connect) '+now)
                        elif isinstance(event,list) and event:
                            trace_live('in','socketio_event',str(event[0])[:60])
                            with LIVE_LOCK:
                                if event[0]=='CONTROL_GRANTED':
                                    LIVE['control_state']='Control granted (event)'
                                    LIVE['control_message']='CONTROL_GRANTED received; confirm masterDeviceId in telemetry'
                                elif event[0]=='CONTROL_DENIED':
                                    LIVE['control_state']='Control denied'
                                    LIVE['control_message']='CONTROL_DENIED: '+str(event[1] if len(event)>1 else 'No reason provided')[:160]

                    except (ValueError,TypeError):trace_live('local','parse_error','Socket.IO event parse failed')
                    continue
                trace_live('in','engine_other',f'prefix={msg[:2]!r}, bytes={len(msg)}')
            if reason.startswith('Remote WebSocket close frame'):break
    except (OSError,EOFError,ValueError) as e:
        reason=f"{type(e).__name__}: {e}"
        with LIVE_LOCK:LIVE['last_error']=reason
        trace_live('local','exception',reason)
    finally:
        if LIVE_STOP.is_set():reason="Explicit disconnect or server shutdown"
        if sock:
            try:ws_send(sock,8,struct.pack('!H',1000))
            except (OSError,ValueError):pass
            try:sock.close()
            except OSError:pass
        trace_live('local','disconnect',reason)
        with LIVE_LOCK:LIVE_SOCKET=None;CONTROL_PENDING=None;globals()['MESSAGE_PENDING']=None;LIVE.update(connected=False,connecting=False,control_state='Disconnected',disconnect_reason=reason)

def live_connect():
    global LIVE_THREAD
    with LIVE_LOCK:
        if LIVE['connected'] or LIVE['connecting']:return live_snapshot()
        LIVE_STOP.clear();        LIVE.update(connected=False,connecting=True,last_error=None,status=None,events=0,ping_received=0,pong_sent=0,ws_ping_received=0,ws_pong_sent=0,last_ping=None,last_pong=None,last_frame=None,close_code=None,control_state='Not requested',control_message=None,control_requested_at=None,
                    started=time.strftime('%Y-%m-%d %H:%M:%S'),last_update=None,disconnect_reason=None,trace=[],namespace_connected=False,last_engine_frame=None,connected_at=None,probe_sent=0,probe_received=0,last_probe_sent=None,last_probe_reply=None)
        LIVE_THREAD=threading.Thread(target=live_worker,daemon=True)
        LIVE_THREAD.start()
        return live_snapshot()

def control_action(action):
    global CONTROL_PENDING
    if action=='releaseControl': WATCHDOG['control']=False
    if action not in ('takeControl','releaseControl'):
        return 400,{'ok':False,'error':'Unsupported action'}
    with LIVE_LOCK:
        if not LIVE['connected'] or LIVE_SOCKET is None or not LIVE['status']:
            return 409,{'ok':False,'error':'Connect Live and wait for current telemetry first'}
        if time.time()-time.mktime(time.strptime(LIVE['last_update'],'%Y-%m-%d %H:%M:%S'))>20:
            return 409,{'ok':False,'error':'Telemetry is stale; action refused'}
        if CONTROL_PENDING or LIVE['control_state'] in ('Request pending','Release pending'):
            return 409,{'ok':False,'error':'Another control request is pending'}
        owner=LIVE['status'].get('masterDeviceId')
        if action=='takeControl':
            if owner is not None:
                return 409,{'ok':False,'error':'Control already owned by '+str(owner)}
            LIVE['control_state']='Request pending'
        else:
            if owner!=CONTROL_CLIENT:
                return 409,{'ok':False,'error':'Release refused: this client is not the confirmed owner'}
            LIVE['control_state']='Release pending'
        CONTROL_PENDING=action
        LIVE['control_message']='Queued '+action
        return 200,{'ok':True,'queued':action,'note':'Await updated masterDeviceId to confirm result'}

def live_disconnect():
    # Disconnecting a control-owning session may release control at the telescope;
    # prefer explicit Release Control first and verify ownership is cleared.
    LIVE_STOP.set()
    with LIVE_LOCK:sock=LIVE_SOCKET
    if sock:
        try:sock.shutdown(socket.SHUT_RDWR)
        except OSError:pass
    return {'ok':True,'message':'Disconnect requested'}

def _config_path():
    dirs=stellina_auth._data_dirs()
    for d in dirs:
        f=d/'stellina_config.json'
        if f.exists(): return f
    return dirs[0]/'stellina_config.json'   # default write location (next to the executable when bundled)
CONFIG_PATH=_config_path()
DIAG={'unlocked':False}
def diag_password_hash():
    env=os.environ.get('STELLINA_DIAG_PASSWORD')
    if env: return hashlib.sha256(env.encode()).hexdigest()
    try:
        d=json.loads(CONFIG_PATH.read_text(encoding='utf-8'))
        h=(d.get('diagnostics_password_sha256') or '').strip()
        return h or None
    except (OSError,ValueError): return None
# ---------- Keep the computer awake (macOS caffeinate / Windows SetThreadExecutionState / Linux systemd-inhibit) ----------
import subprocess, platform
KEEPAWAKE={'mode':'auto','active':False,'reason':None,'method':None,'error':None,'proc':None}
KEEPAWAKE_MODES=('auto','always','off')
KEEPAWAKE_EVT=threading.Event()
def _cfg_read():
    try: return json.loads(CONFIG_PATH.read_text(encoding='utf-8'))
    except (OSError,ValueError): return {}
def _cfg_write(upd):
    d=_cfg_read(); d.update(upd)
    try: CONFIG_PATH.write_text(json.dumps(d,indent=2),encoding='utf-8')
    except OSError: pass
def _awake_on():
    sysname=platform.system()
    try:
        if sysname=='Darwin':
            # -i: no idle sleep, -s: no system sleep on AC power, -m: keep disks awake; ends with this process (-w)
            KEEPAWAKE['proc']=subprocess.Popen(['caffeinate','-i','-s','-m','-w',str(os.getpid())],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            KEEPAWAKE['method']='caffeinate'
        elif sysname=='Windows':
            import ctypes
            ES_CONTINUOUS,ES_SYSTEM_REQUIRED,ES_AWAYMODE=0x80000000,0x00000001,0x00000040
            if not ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS|ES_SYSTEM_REQUIRED|ES_AWAYMODE):
                ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS|ES_SYSTEM_REQUIRED)
            KEEPAWAKE['method']='SetThreadExecutionState'
        else:
            KEEPAWAKE['proc']=subprocess.Popen(['systemd-inhibit','--what=sleep:idle','--who=Stellina Control','--why=Telescope session running','--mode=block','sleep','infinity'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            KEEPAWAKE['method']='systemd-inhibit'
        KEEPAWAKE.update(active=True,error=None)
    except Exception as e:
        KEEPAWAKE.update(active=False,error=str(e))
def _awake_off():
    p=KEEPAWAKE.get('proc')
    if p is not None:
        try: p.terminate()
        except Exception: pass
    if KEEPAWAKE.get('method')=='SetThreadExecutionState':
        try:
            import ctypes; ctypes.windll.kernel32.SetThreadExecutionState(0x80000000)
        except Exception: pass
    KEEPAWAKE.update(active=False,proc=None)
def _awake_needed():
    """auto: while the telescope is doing anything, a plan is running/waiting, or an end-of-plan action is armed or running."""
    if KEEPAWAKE['mode']=='always': return 'always on'
    if KEEPAWAKE['mode']=='off': return None
    with LIVE_LOCK: st=dict(LIVE.get('status') or {}); conn=LIVE['connected']
    op=st.get('currentOperation')
    if isinstance(op,dict) and not op.get('stopped'):
        KEEPAWAKE['until']=max(KEEPAWAKE.get('until',0),time.time()+30*60)   # stay awake 30 min after the last busy status (connection drops)
        return 'telescope busy: '+str(op.get('type') or 'operation').replace('_',' ').lower()
    if any(isinstance(o,dict) and not o.get('stopped') for o in (st.get('otherCurrentOperations') or [])):
        KEEPAWAKE['until']=max(KEEPAWAKE.get('until',0),time.time()+30*60)
        return 'capture running'
    if PLAN_END.get('armed'): return 'end-of-plan action armed'
    if time.time()<KEEPAWAKE.get('until',0):
        return 'plan window / reconnect grace until '+time.strftime('%H:%M',time.localtime(KEEPAWAKE['until']))
    if (PLAN_END.get('last') or {}).get('state')=='running': return 'end-of-plan action running'
    return None
WATCHDOG={'wanted':False,'control':False,'reconnects':0,'last':None}
def watchdog_loop():
    """Reconnect Live after a drop (Wi-Fi blip, Mac switched networks) and take control back if we had it,
    so a running plan's end actions (park / TIFF / shutdown) still happen. Only after the user connected."""
    while True:
        time.sleep(20)
        try:
            with LIVE_LOCK:
                conn=LIVE['connected']; connecting=LIVE['connecting']; st=dict(LIVE.get('status') or {})
            if conn and st.get('masterDeviceId')==CONTROL_CLIENT: WATCHDOG['control']=True
            if WATCHDOG['wanted'] and not conn and not connecting:
                WATCHDOG['reconnects']+=1; WATCHDOG['last']=time.strftime('%Y-%m-%d %H:%M:%S')+' reconnecting'
                trace_live('out','watchdog','connection lost — reconnecting (#%d)'%WATCHDOG['reconnects'])
                live_connect(); continue
            if conn and WATCHDOG['control'] and st and st.get('masterDeviceId') is None:
                code,res=control_action('takeControl')
                WATCHDOG['last']=time.strftime('%Y-%m-%d %H:%M:%S')+' re-took control (%s)'%code
                trace_live('out','watchdog','re-take control -> %s'%code)
        except Exception as e:
            WATCHDOG['last']='error: %s'%e

def keepawake_loop():
    m=_cfg_read().get('keep_awake')
    if m in KEEPAWAKE_MODES: KEEPAWAKE['mode']=m
    while True:
        try:
            why=_awake_needed(); KEEPAWAKE['reason']=why
            if why and not KEEPAWAKE['active']: _awake_on(); trace_live('out','keepawake','on (%s) via %s'%(why,KEEPAWAKE.get('method')))
            elif not why and KEEPAWAKE['active']: _awake_off(); trace_live('out','keepawake','off')
            p=KEEPAWAKE.get('proc')
            if KEEPAWAKE['active'] and p is not None and p.poll() is not None:   # helper died -> restart
                KEEPAWAKE['active']=False
            if KEEPAWAKE['active'] and KEEPAWAKE.get('method')=='SetThreadExecutionState': _awake_on()   # refresh from this same thread
        except Exception as e: KEEPAWAKE['error']=str(e)
        KEEPAWAKE_EVT.wait(15); KEEPAWAKE_EVT.clear()
def keepawake_public():
    return {**{k:KEEPAWAKE.get(k) for k in ('mode','active','reason','method','error')},'platform':platform.system(),'reconnects':WATCHDOG['reconnects'],'watchdog':WATCHDOG['last']}

def diag_locked(): return bool(diag_password_hash())
def diag_blocked(): return diag_locked() and not DIAG['unlocked']
GATED_GET={'/api/telescope/ports','/api/telescope/handshake','/api/telescope/websocket',
           '/api/telescope/auth/netcheck','/api/telescope/auth/status','/api/telescope/http-readonly'}
GATED_POST={'/api/telescope/auth/request','/api/telescope/auth/verify','/api/telescope/time/set'}

class Handler(BaseHTTPRequestHandler):
    def send(self, status, data, content_type='application/json'):
        raw=(json.dumps(data,ensure_ascii=False).encode() if content_type=='application/json' else data)
        self.send_response(status);self.send_header('Content-Type',content_type+'; charset=utf-8');self.send_header('Content-Length',str(len(raw)));self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(raw)
    def do_GET(self):
        if self.path=='/api/config':
            return self.send(200,{'keyInstalled':stellina_auth.KEY_LOADED,'backend':stellina_auth.BACKEND,
                                  'diagnosticsLocked':diag_blocked(),'diagnosticsPasswordSet':diag_locked(),
                                  'passwordFromEnv':bool(os.environ.get('STELLINA_DIAG_PASSWORD'))})
        if self.path.split('?',1)[0] in GATED_GET and diag_blocked():
            return self.send(403,{'error':'Diagnostics are locked. Unlock on the Diagnostics tab.'})
        _vend={'/static/vendor/aladin-3.8.2.js':('aladin-3.8.2.js','text/javascript; charset=utf-8'),
               '/static/vendor/sky/stars.bin':('sky/stars.bin','application/octet-stream'),
               '/static/vendor/sky/dso.json':('sky/dso.json','application/json'),
               '/static/vendor/sky/outlines.json':('sky/outlines.json','application/json')}
        if self.path in _vend:
            fn,ct=_vend[self.path]; raw=(ROOT/'static'/'vendor'/fn).read_bytes()
            self.send_response(200);self.send_header('Content-Type',ct);self.send_header('Content-Length',str(len(raw)));self.send_header('Cache-Control','max-age=604800');self.end_headers();self.wfile.write(raw);return
        if self.path in ('/','/index.html'):
            self.send(200,(ROOT/'static'/'index.html').read_bytes(),'text/html')
        elif self.path.startswith('/api/ftp/list?'):
            try:
                q=parse_qs(urlsplit(self.path).query)
                self.send(200,list_ftp(q.get('path',['/'])[0]))
            except (ValueError,ftplib.all_errors,OSError) as e:self.send(502,{'error':str(e)})
        elif self.path.startswith('/api/ftp/download?'):
            try:
                q=parse_qs(urlsplit(self.path).query)
                content,name=download_ftp(q.get('path',['/'])[0])
                self.send_response(200)
                self.send_header('Content-Type','application/octet-stream')
                self.send_header('Content-Disposition',"attachment; filename*=UTF-8''"+quote(name))
                self.send_header('Content-Length',str(len(content)))
                self.send_header('Cache-Control','no-store')
                self.end_headers();self.wfile.write(content)
            except (ValueError,ftplib.all_errors,OSError) as e:self.send(502,{'error':str(e)})
        elif self.path=='/api/telescope/http-readonly':
            # Non-mutating GET only. Never contact the third-party authorization server.
            # A 401/403/404 response still establishes HTTP server reachability.
            import http.client
            try:
                conn=http.client.HTTPConnection(FTP_HOST,8082,timeout=4)
                try:
                    conn.request('GET','/',headers={'Accept':'application/json','Connection':'close'})
                    response=conn.getresponse()
                    raw=response.read(512)
                    self.send(200,{'reachable':True,'httpStatus':response.status,
                      'reason':response.reason,'contentType':response.getheader('Content-Type'),
                      'responsePreview':raw.decode('utf-8','replace'),
                      'authorization':'NOT ATTEMPTED','initialization':'NOT SENT',
                      'externalService':'NOT CONTACTED'})
                finally:conn.close()
            except (OSError,TimeoutError) as e:
                self.send(502,{'reachable':False,'error':str(e),'initialization':'NOT SENT'})
        elif self.path.startswith('/api/catalog/search?'):
            try:
                q=parse_qs(urlsplit(self.path).query)
                self.send(200,{'results':stellina_catalog.search(q.get('q',[''])[0])})
            except (ValueError,OSError) as e: self.send(502,{'error':str(e)})
        elif self.path.startswith('/api/telescope/frame?'):
            import http.client
            q=parse_qs(urlsplit(self.path).query)
            url=q.get('url',[''])[0]
            if not re.match(r'^/files/[A-Za-z0-9._/%+-]{1,400}\.(jpg|jpeg|png)$',url,re.I) or '..' in url:
                return self.send(400,{'ok':False,'error':'bad frame url'})
            try:
                conn=http.client.HTTPConnection(FTP_HOST,8082,timeout=20)
                conn.request('GET',url,headers={'Connection':'close'})
                r=conn.getresponse(); data=r.read(20*1024*1024); conn.close()
                if r.status!=200: return self.send(502,{'ok':False,'error':'HTTP %s'%r.status})
                self.send_response(200)
                self.send_header('Content-Type',r.getheader('Content-Type') or 'image/jpeg')
                self.send_header('Content-Length',str(len(data)))
                self.send_header('Cache-Control','max-age=3600'); self.end_headers(); self.wfile.write(data)
            except OSError as e:
                try: self.send(502,{'ok':False,'error':str(e)})
                except OSError: pass
            return
        elif self.path.startswith('/api/telescope/export/download?'):
            import http.client
            q=parse_qs(urlsplit(self.path).query)
            url=q.get('url',[''])[0]; fn=q.get('name',['stellina.tif'])[0]
            if not re.match(r'^/files/[A-Za-z0-9._/%+-]{1,400}$',url) or '..' in url:
                return self.send(400,{'ok':False,'error':'bad export url'})
            if not re.match(r'^[A-Za-z0-9._-]{1,120}$',fn): fn='stellina.tif'
            try:
                conn=http.client.HTTPConnection(FTP_HOST,8082,timeout=120)
                conn.request('GET',url,headers={'Connection':'close'})
                r=conn.getresponse()
                if r.status not in (200,206):
                    r.read(); conn.close(); return self.send(502,{'ok':False,'error':'Telescope returned HTTP %s for %s'%(r.status,url)})
                self.send_response(200)
                self.send_header('Content-Type','image/tiff')
                self.send_header('Content-Disposition',"attachment; filename*=UTF-8''"+quote(fn))
                ln=r.getheader('Content-Length')
                if ln: self.send_header('Content-Length',ln)
                self.send_header('Cache-Control','no-store'); self.end_headers()
                while True:
                    chunk=r.read(1<<20)
                    if not chunk: break
                    self.wfile.write(chunk)
                conn.close()
            except OSError as e:
                try: self.send(502,{'ok':False,'error':str(e)})
                except OSError: pass
            return
        elif self.path.startswith('/api/telescope/userstorage/download?'):
            try:
                q=parse_qs(urlsplit(self.path).query)
                res=userstorage_download(q.get('path',[''])[0], q.get('name',[''])[0])
            except (ValueError,OSError) as e:
                return self.send(400,{'ok':False,'error':str(e)})
            if res.get('ok'):
                data=res['data']
                self.send_response(200)
                self.send_header('Content-Type','application/octet-stream')
                self.send_header('Content-Disposition',"attachment; filename*=UTF-8''"+quote(res['name']))
                self.send_header('Content-Length',str(len(data)))
                self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(data)
            else:
                self.send(502,res)
        elif self.path.startswith('/api/telescope/userstorage?'):
            q=parse_qs(urlsplit(self.path).query)
            self.send(200,userstorage_list(q.get('path',['/'])[0]))
        elif self.path=='/api/telescope/auth/netcheck':
            self.send(200,auth_netcheck())
        elif self.path=='/api/telescope/auth/status':
            self.send(200,auth_diagnostics())
        elif self.path=='/api/telescope/sensors':
            self.send(200,appstatus_sensors())
        elif self.path=='/api/telescope/live/status':
            self.send(200,live_snapshot())
        elif self.path=='/api/telescope/websocket':
            self.send(200,websocket_diagnostic())
        elif self.path=='/api/telescope/ports':
            self.send(200,telescope_probe())
        elif self.path=='/api/telescope/handshake':
            self.send(200,socketio_handshake())
        elif self.path=='/api/ftp/status':
            self.send(200,ftp_status())
        elif self.path=='/api/keepawake':
            self.send(200,keepawake_public())
        elif self.path=='/api/info':
            self.send(200,{'version':VERSION,'mode':'FULL CONTROL','default_ip':'10.0.0.1'})
        else:self.send(404,{'error':'Not found'})
    def do_POST(self):
        if self.path=='/api/ftp/save-folder':
            try:
                n=int(self.headers.get('Content-Length','0'))
                if not 1<=n<=4096: raise ValueError('Invalid request size')
                body=json.loads(self.rfile.read(n))
                if not isinstance(body,dict): raise ValueError('JSON object expected')
                return self.send(200,save_ftp_folder(body.get('path')))
            except (ValueError,TypeError,ftplib.all_errors,OSError,zipfile.BadZipFile) as e:
                return self.send(502,{'ok':False,'error':str(e)})
        if self.path=='/api/ftp/save':
            try:
                n=int(self.headers.get('Content-Length','0'))
                if not 1<=n<=65536: raise ValueError('Invalid request size')
                body=json.loads(self.rfile.read(n))
                if not isinstance(body,dict): raise ValueError('JSON object expected')
                return self.send(200,save_ftp_files(body.get('paths')))
            except (ValueError,TypeError,ftplib.all_errors,OSError,zipfile.BadZipFile) as e:
                return self.send(502,{'ok':False,'error':str(e)})
        if self.path=='/api/diag/unlock':
            try:
                n=int(self.headers.get('Content-Length','0'))
                pw=json.loads(self.rfile.read(n)).get('password','') if 0<n<=1024 else ''
            except (ValueError,json.JSONDecodeError): pw=''
            h=diag_password_hash()
            if h and hashlib.sha256(pw.encode()).hexdigest()==h:
                DIAG['unlocked']=True
                return self.send(200,{'ok':True})
            return self.send(200,{'ok':False,'error':'Wrong password'})
        if self.path=='/api/diag/setpassword':
            if os.environ.get('STELLINA_DIAG_PASSWORD'):
                return self.send(409,{'ok':False,'error':'Password is set via the STELLINA_DIAG_PASSWORD environment variable; change it there.'})
            try:
                n=int(self.headers.get('Content-Length','0')); body=json.loads(self.rfile.read(n)) if 0<n<=2048 else {}
            except (ValueError,json.JSONDecodeError): body={}
            cur=diag_password_hash()
            if cur and hashlib.sha256(str(body.get('current','')).encode()).hexdigest()!=cur:
                return self.send(403,{'ok':False,'error':'Current password is wrong'})
            new=str(body.get('new',''))
            try:
                try: d=json.loads(CONFIG_PATH.read_text(encoding='utf-8'))
                except (OSError,ValueError): d={}
                d['diagnostics_password_sha256']=hashlib.sha256(new.encode()).hexdigest() if new else ''
                CONFIG_PATH.write_text(json.dumps(d,indent=2),encoding='utf-8')
            except OSError as e:
                return self.send(500,{'ok':False,'error':'Could not save the password: '+str(e)})
            if new: DIAG['unlocked']=False
            return self.send(200,{'ok':True,'locked':bool(new)})
        if self.path in GATED_POST and diag_blocked():
            return self.send(403,{'ok':False,'error':'Diagnostics are locked. Unlock on the Diagnostics tab.'})
        if self.path=='/api/telescope/auth/request':
            status,result=request_authorization()
            return self.send(status,result)
        if self.path=='/api/telescope/plan/start':
            try:
                n=int(self.headers.get('Content-Length','0'))
                if n<1 or n>65536: raise ValueError('Invalid request size')
                params=json.loads(self.rfile.read(n))
                if not isinstance(params,dict): raise ValueError('JSON object expected')
            except (ValueError,json.JSONDecodeError) as e: return self.send(400,{'ok':False,'error':str(e)})
            status,result=start_plan(params)
            return self.send(status,result)
        if self.path=='/api/keepawake':
            try:
                n=int(self.headers.get('Content-Length','0')); body=json.loads(self.rfile.read(n)) if 0<n<=256 else {}
                m=str(body.get('mode'))
                if m not in KEEPAWAKE_MODES: raise ValueError('mode must be auto, always or off')
            except (ValueError,json.JSONDecodeError) as e: return self.send(400,{'ok':False,'error':str(e)})
            KEEPAWAKE['mode']=m; _cfg_write({'keep_awake':m})
            KEEPAWAKE_EVT.set(); time.sleep(0.3)   # applied by the keep-awake thread (Windows state is per thread)
            return self.send(200,{'ok':True,**keepawake_public()})
        if self.path=='/api/telescope/plan/endaction':
            try:
                n=int(self.headers.get('Content-Length','0')); body=json.loads(self.rfile.read(n)) if 0<n<=256 else {}
                act=str(body.get('action',PLAN_END['action']))
                if act not in PLAN_END_ACTIONS: raise ValueError('action must be none, park or shutdown')
                if 'saveTiff' in body: PLAN_END['tiff']=bool(body['saveTiff'])
            except (ValueError,json.JSONDecodeError) as e: return self.send(400,{'ok':False,'error':str(e)})
            with LIVE_LOCK: st=dict(LIVE.get('status') or {})
            op=st.get('currentOperation'); running=isinstance(op,dict) and op.get('type')=='PLAN' and not op.get('stopped')
            PLAN_END['action']=act
            if act=='none' and not PLAN_END['tiff']: PLAN_END['armed']=False
            elif running: PLAN_END.update(armed=True,seen=True,idle=0,userStopped=False)
            return self.send(200,{'ok':True,'planRunning':running,**plan_end_public()})
        if self.path=='/api/telescope/plan/stop':
            PLAN_END['userStopped']=True
            status,result=simple_command('/v1/planner/stopPlan')
            return self.send(status,result)
        if self.path=='/api/telescope/darks/start':
            try:
                n=int(self.headers.get('Content-Length','0'))
                if n<1 or n>2048: raise ValueError('Invalid request size')
                params=json.loads(self.rfile.read(n))
                if not isinstance(params,dict): raise ValueError('JSON object expected')
            except (ValueError,json.JSONDecodeError) as e: return self.send(400,{'ok':False,'error':str(e)})
            status,result=start_darks(params)
            return self.send(status,result)
        if self.path=='/api/telescope/darks/stop':
            status,result=simple_command('/v1/expertMode/stopStorageAcquisition')
            return self.send(status,result)
        if self.path=='/api/telescope/darklib/generate':
            status,result=simple_command('/v1/darkManager/generateDark',forbid_busy_types=('OBSERVATION','AUTO_INIT','PLAN','PARK','GENERATE_DARK'),timeout=20)
            return self.send(status,result)
        if self.path=='/api/telescope/darklib/stop':
            status,result=simple_command('/v1/darkManager/stopGenerateDark')
            return self.send(status,result)
        if self.path=='/api/telescope/export/tiff':
            status,result=export_tiff()
            return self.send(status,result)
        if self.path in ('/api/telescope/settings/livefocus','/api/telescope/settings/fullres','/api/telescope/focus/restart'):
            try:
                n=int(self.headers.get('Content-Length','0'))
                body=json.loads(self.rfile.read(n)) if 0<n<=1024 else {}
                if not isinstance(body,dict): raise ValueError('JSON object expected')
            except (ValueError,json.JSONDecodeError) as e: return self.send(400,{'ok':False,'error':str(e)})
            if self.path.endswith('livefocus'): status,result=set_live_focus(bool(body.get('enabled')))
            elif self.path.endswith('fullres'): status,result=set_full_resolution(bool(body.get('enabled')))
            else: status,result=restart_autofocus(body.get('restartCapture',True) is not False)
            return self.send(status,result)
        if self.path=='/api/telescope/settings/darkusage':
            try:
                n=int(self.headers.get('Content-Length','0'))
                body=json.loads(self.rfile.read(n)) if 0<n<=1024 else {}
                if not isinstance(body,dict): raise ValueError('JSON object expected')
            except (ValueError,json.JSONDecodeError) as e: return self.send(400,{'ok':False,'error':str(e)})
            status,result=set_dark_usage(bool(body.get('enabled')))
            return self.send(status,result)
        if self.path=='/api/telescope/observe/start':
            try:
                n=int(self.headers.get('Content-Length','0'))
                if n<1 or n>2048: raise ValueError('Invalid request size')
                params=json.loads(self.rfile.read(n))
                if not isinstance(params,dict): raise ValueError('JSON object expected')
            except (ValueError,json.JSONDecodeError) as e: return self.send(400,{'ok':False,'error':str(e)})
            status,result=start_observation(params)
            return self.send(status,result)
        if self.path=='/api/telescope/observe/stop':
            status,result=simple_command('/v1/general/stopObservation',timeout=45,slow=True,
                 slow_note='Stop sent. The telescope finishes the current frame and saves the stack before it replies — watch the Observation status; it can take up to a minute.')
            return self.send(status,result)
        if self.path=='/api/telescope/userstorage/delete':
            try:
                n=int(self.headers.get('Content-Length','0'))
                if n<1 or n>8192: raise ValueError('Invalid request size')
                body=json.loads(self.rfile.read(n))
                if not isinstance(body,dict): raise ValueError('JSON object expected')
            except (ValueError,json.JSONDecodeError) as e: return self.send(400,{'ok':False,'error':str(e)})
            status,result=delete_user_folders(body.get('folderPaths'))
            return self.send(status,result)
        if self.path=='/api/telescope/shutdown':
            status,result=simple_command('/v1/board/requestShutdown',forbid_busy_types=('OBSERVATION','AUTO_INIT','PLAN','PARK'),timeout=30)
            return self.send(status,result)
        if self.path=='/api/telescope/motors/registers':
            status,result=motor_registers()
            return self.send(status,result)
        if self.path=='/api/telescope/openarm':
            status,result=open_arm()
            return self.send(status,result)
        if self.path=='/api/telescope/park':
            status,result=simple_command('/v1/general/park',forbid_busy_types=('OBSERVATION','AUTO_INIT','PLAN'),timeout=90,slow=True)
            return self.send(status,result)
        if self.path=='/api/telescope/init/start':
            try:
                n=int(self.headers.get('Content-Length','0'))
                if n<1 or n>2048: raise ValueError('Invalid request size')
                params=json.loads(self.rfile.read(n))
                if not isinstance(params,dict): raise ValueError('JSON object expected')
            except (ValueError,json.JSONDecodeError) as e: return self.send(400,{'ok':False,'error':str(e)})
            status,result=start_autoinit(params)
            return self.send(status,result)
        if self.path=='/api/telescope/init/stop':
            status,result=stop_autoinit()
            return self.send(status,result)
        if self.path=='/api/telescope/time/set':
            status,result=set_system_time()
            return self.send(status,result)
        if self.path=='/api/telescope/auth/verify':
            status,result=verify_authorization()
            return self.send(status,result)

        if self.path=='/api/telescope/control/take':
            status,result=control_action('takeControl')
            return self.send(status,result)
        if self.path=='/api/telescope/control/release':
            status,result=control_action('releaseControl')
            return self.send(status,result)
        if self.path=='/api/telescope/live/connect':
            WATCHDOG['wanted']=True
            return self.send(200,live_connect())
        if self.path=='/api/telescope/live/disconnect':
            WATCHDOG.update(wanted=False,control=False)
            return self.send(200,live_disconnect())
        if self.path=='/api/ftp/disconnect':
            close_ftp()
            return self.send(200,{'ok':True,'connected':False})
        if self.path!='/api/diagnose':return self.send(404,{'error':'Not found'})
        try:
            n=int(self.headers.get('Content-Length','0'))
            if n<1 or n>4096:raise ValueError('Invalid request size')
            d=json.loads(self.rfile.read(n));ip=valid_host(d.get('ip','10.0.0.1'))
            port=int(d.get('port',80))
            if not 1<=port<=65535:raise ValueError('Port out of range')
            # On the confirmed FTP endpoint, avoid a separate TCP probe and
            # avoid opening a second FTP session for diagnostics.
            if ip==FTP_HOST and port==21:
                started=time.monotonic()
                with FTP_LOCK:
                    ftp=ftp_session()
                    welcome=ftp.getwelcome()
                elapsed=round((time.monotonic()-started)*1000)
                tcp={'ok':True,'message':'Shared FTP session ready','ms':elapsed}
                ftp_status_result={'ok':True,'welcome':welcome,'shared_session':True}
            else:
                tcp=probe(ip,port)
                ftp_status_result=None
            result={'ip':ip,'port':port,'tcp':tcp,'ftp':ftp_status_result,'http':http_probe(ip,port) if tcp['ok'] and port!=21 else None,'timestamp':time.strftime('%Y-%m-%d %H:%M:%S')}
            self.send(200,result)
        except (ValueError,TypeError,json.JSONDecodeError) as e:self.send(400,{'error':str(e)})
    def log_message(self,fmt,*args):print('[Stellina Control]',fmt%args)

def _lan_ip():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    try: s.connect(('10.0.0.1',80)); return s.getsockname()[0]
    except OSError:
        try: s.connect(('8.8.8.8',80)); return s.getsockname()[0]
        except OSError: return None
    finally: s.close()

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--set-diag-password':
        import getpass
        pw=getpass.getpass('New diagnostics password (empty = remove lock): ')
        try: d=json.loads(CONFIG_PATH.read_text(encoding='utf-8'))
        except (OSError,ValueError): d={}
        d['diagnostics_password_sha256']=hashlib.sha256(pw.encode()).hexdigest() if pw else ''
        CONFIG_PATH.write_text(json.dumps(d,indent=2),encoding='utf-8')
        print('Saved to', CONFIG_PATH.name, '— the Telescope Diagnostics and Diagnostics tabs are now', 'locked.' if pw else 'open.')
        raise SystemExit(0)
    shown=HOST if HOST not in ('0.0.0.0','') else (_lan_ip() or '<this-device-ip>')
    print(f'Stellina Control v{VERSION}: http://{shown}:{PORT}')
    print('Authorization key:', 'loaded ('+stellina_auth.KEY_SOURCE+')' if stellina_auth.KEY_LOADED else 'NOT installed — read-only mode (add stellina_key.json to control the telescope)')
    if HOST in ('0.0.0.0',''):
        print(f'  Reachable from other devices on this network at http://{shown}:{PORT}  (e.g. your iPhone on the Pi hotspot)')
    print('Auto-Init moves the arm when you start it. No GoTo or exposure commands are implemented.')
    try:
        server=ThreadingHTTPServer((HOST,PORT),Handler)
    except OSError as e:
        if getattr(e,'errno',None) in (48,98,10048):  # EADDRINUSE: macOS / Linux / Windows
            print(f'\nPort {PORT} is already in use — Stellina Control is probably already running.')
            print(f'  • Open the running copy at  http://{shown}:{PORT}')
            print(f'  • Or quit the other copy (close its window / Ctrl-C its terminal), then start again.')
            print(f'  • Or use a different port:  STELLINA_PORT=8767 ./start.command')
            raise SystemExit(1)
        raise
    # Auto-open a browser only for a local desktop run, not headless (Raspberry Pi) or LAN-bound.
    if HOST in ('127.0.0.1','localhost') and os.environ.get('STELLINA_NO_BROWSER') not in ('1','true','yes'):
        threading.Timer(1,lambda:webbrowser.open(f'http://{HOST}:{PORT}')).start()
    threading.Thread(target=idle_cleanup,daemon=True).start()
    threading.Thread(target=keepawake_loop,daemon=True).start()
    threading.Thread(target=watchdog_loop,daemon=True).start()
    try:server.serve_forever()
    except KeyboardInterrupt:print('\nStopped.')
    finally:live_disconnect();close_ftp();_awake_off();server.server_close()
