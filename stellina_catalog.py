"""Build a startObservation body the Stellina firmware accepts.

Rules and the 421-object catalog (catalog.json) are from pyvaonis (MIT,
https://github.com/DouweM/pyvaonis), which reverse-engineered the official app's
observation_rules.json. The firmware returns HTTP 500 (CHECKPARAMS) unless the
histogram/background params exactly match what doStacking implies, so this mirrors
the app to the letter:

  deep-sky {OP,ODC,ODE,ODOC}  -> doStacking=true + 6 histogram/background params
                                 (per-object from the catalog, else per-type defaults)
  stars / untyped              -> doStacking=false, omit the 6 params
  solar (planet/Moon/Sun)      -> doStacking=false, NO ra/de/rot (firmware resolves),
                                 per-planet gain/exposure overrides
"""
import json, pathlib

_DATA = pathlib.Path(__file__).resolve().parent / 'catalog.json'
_STACKING_TYPES = {'OP', 'ODC', 'ODE', 'ODOC'}
_HISTOGRAM_LOW_BY_TYPE = {'OP': 0.0, 'ODC': -0.75, 'ODE': -1.0, 'ODOC': -1.0}
SOLAR_SYSTEM = {'sun', 'mercury', 'venus', 'moon', 'mars', 'jupiter', 'saturn', 'uranus', 'neptune'}
# Per-planet gain/exposureMicroSec (Stellina) from the app's observation_rules.json.
_SOLAR_PARAMS = {'moon': (50, 40000), 'venus': (50, 40000), 'jupiter': (16, 10000),
                 'saturn': (100, 100000), 'mars': (16, 10000), 'uranus': (200, 500000),
                 'neptune': (270, 2000000)}
# Never image these without the Vaonis solar filter: too close to the Sun, sensor-destroying.
SOLAR_BLOCKED = {'sun', 'mercury'}

_OBJECTS = None
_INDEX = None


def _load():
    global _OBJECTS, _INDEX
    if _OBJECTS is None:
        _OBJECTS = json.loads(_DATA.read_text(encoding='utf-8'))
        _INDEX = {}
        for o in _OBJECTS:
            for key in (o.get('id'), o.get('name'), o.get('shortTitle')):
                if key: _INDEX.setdefault(str(key).lower().replace(' ', ''), o)
    return _OBJECTS, _INDEX


def search(query, limit=12):
    """Case-insensitive substring match on id/name/shortTitle/constellation."""
    objs, _ = _load()
    q = query.lower().strip()
    if not q: return []
    out = []
    for o in objs:
        hay = ' '.join(str(o.get(k, '')) for k in ('id', 'name', 'shortTitle', 'constellationName', 'categoryLabel')).lower()
        if q in hay:
            exp = gain = None; stacking = False
            try:
                body = observation_body(o)
                exp = body.get('exposureMicroSec'); gain = body.get('gain'); stacking = bool(body.get('doStacking'))
            except (ValueError, KeyError, TypeError):
                pass
            out.append({'id': o['id'], 'name': o.get('name') or o['id'], 'type': o.get('type'),
                        'category': o.get('categoryLabel'), 'constellation': o.get('constellationName'),
                        'magnitude': o.get('magnitude'), 'duration': o.get('duration'),
                        'solar': o['id'].lower() in SOLAR_SYSTEM,
                        'exposureMicroSec': exp, 'gain': gain, 'stacking': stacking,
                        'ra': o.get('ra'), 'de': o.get('de'), 'rot': o.get('orientation')})
    out.sort(key=lambda e: (e['name'].lower() != q and e['id'].lower() != q, e['name'].lower()))
    return out[:limit]


def get_object(object_id):
    _, idx = _load()
    return idx.get(str(object_id).lower().replace(' ', ''))


def observation_body(obj):
    """ObservationBody dict (None fields dropped) for a catalog entry, or raise ValueError."""
    oid = obj['id']
    name = obj.get('name') or oid
    is_solar = oid.lower() in SOLAR_SYSTEM
    if is_solar:
        if oid.lower() in SOLAR_BLOCKED:
            raise ValueError(f'{name} is at or too near the Sun; imaging it without the Vaonis solar filter would destroy the sensor. Refused.')
        gain, exp = _SOLAR_PARAMS.get(oid.lower(), (obj.get('gain'), obj.get('exposure')))
        body = {'objectId': oid, 'objectName': name, 'objectType': obj.get('type') or '',
                'targetType': 'CATALOG', 'doStacking': False,
                'observationType': 'STANDARD', 'algorithm': 'AUTO'}
        if gain is not None: body['gain'] = gain
        if exp is not None: body['exposureMicroSec'] = exp
        return body
    if obj.get('ra') is None or obj.get('de') is None:
        raise ValueError(f'{name} has no coordinates in the catalog.')
    body = {'objectId': oid, 'objectName': name, 'objectType': obj.get('type') or '',
            'targetType': 'CATALOG', 'ra': obj['ra'], 'de': obj['de'],
            'observationType': 'STANDARD', 'algorithm': 'AUTO'}
    if obj.get('orientation') is not None: body['rot'] = obj['orientation']
    if obj.get('gain') is not None: body['gain'] = obj['gain']
    if obj.get('exposure') is not None: body['exposureMicroSec'] = obj['exposure']
    if obj.get('type') not in _STACKING_TYPES:  # stars / untyped -> single frames
        body['doStacking'] = False
        return body
    low = obj.get('histogramLow')
    if low is None: low = _HISTOGRAM_LOW_BY_TYPE.get(obj.get('type'), 0.0)
    body.update(doStacking=True, histogramEnabled=bool(obj.get('histogramEnabled', True)),
                histogramLow=float(low), histogramMedium=float(obj.get('histogramMedium', 5)),
                histogramHigh=float(obj.get('histogramHigh', 0)),
                backgroundEnabled=bool(obj.get('backgroundEnabled', True)),
                backgroundPolyorder=float(obj.get('backgroundPolyorder', 2)))
    return body


def manual_body(ra, de, name='', gain=None, exposure_us=None, stacking=False, rot=0.0):
    """Body for a manual RA/Dec target. Stacking sends the 6 deep-sky params the firmware requires."""
    body = {'objectId': '', 'objectName': name or '', 'objectType': '', 'targetType': 'MANUAL',
            'ra': float(ra), 'de': float(de), 'observationType': 'STANDARD', 'algorithm': 'AUTO'}
    if rot is not None: body['rot'] = float(rot)
    if gain is not None: body['gain'] = int(gain)
    if exposure_us is not None: body['exposureMicroSec'] = int(exposure_us)
    if stacking:
        body.update(doStacking=True, histogramEnabled=True, histogramLow=-0.75,
                    histogramMedium=5.0, histogramHigh=0.0, backgroundEnabled=True,
                    backgroundPolyorder=2.0)
    else:
        body['doStacking'] = False
    return body
