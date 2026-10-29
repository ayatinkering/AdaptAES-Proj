"""Vercel entrypoint: stateless API requests using the unchanged research core."""
import json
import threading
from urllib.parse import urlparse
from api.server import Handler
from api import research

_EXPERIMENT_LOCK = threading.Lock()


class handler(Handler):
    def do_POST(self):
        if urlparse(self.path).path != '/api/experiments':
            return super().do_POST()
        try:
            origin = self.headers.get('Origin')
            if origin and urlparse(origin).netloc != self.headers.get('Host'):
                return self.respond({'error': 'Only same-origin requests are accepted.'}, 403)
            size = int(self.headers.get('Content-Length', '0'))
            if self.headers.get_content_type() != 'application/json' or not 0 < size <= 200000:
                raise ValueError('Send a JSON object within the input limit.')
            body = json.loads(self.rfile.read(size))
            if not isinstance(body, dict):
                raise ValueError('Send a JSON object.')
            kind = body.get('kind', 'integral')
            seed = int(body.get('seed', 20261029))
            trials = int(body.get('trials', 1))
            if kind not in ('integral', 'differential', 'linear', 'substitution') or not 1 <= trials <= 3 or not 0 <= seed <= 2**32-1:
                raise ValueError('Choose a supported experiment, 1–3 trials, and a valid seed.')
            # Keep the supplied attack function's RNG binding isolated within an instance.
            with _EXPERIMENT_LOCK:
                result = research.experiments(kind, seed, trials, lambda _: None)
            self.respond({'state': 'done', 'completed': 6*trials, 'total': 6*trials, 'result': result})
        except (ValueError, TypeError, KeyError, OverflowError) as exc:
            self.respond({'error': str(exc)}, 400)
        except Exception:
            self.respond({'error': 'The experiment failed. Check inputs and retry.'}, 500)
