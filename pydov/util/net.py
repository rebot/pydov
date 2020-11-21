from queue import Empty, Queue
from threading import Thread

import requests
import urllib3
from requests.adapters import HTTPAdapter

import pydov

request_timeout = 300


class TimeoutHTTPAdapter(HTTPAdapter):
    """HTTPAdapter which adds a default timeout to requests. Allows timeout
    do be overridden on a per-request basis.
    """

    def __init__(self, *args, **kwargs):
        """Initialisation."""
        self.timeout = request_timeout
        if "timeout" in kwargs:
            self.timeout = kwargs["timeout"]
            del kwargs["timeout"]
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        """Sends PreparedRequest object. Returns Response object.

        Parameters
        ----------
        request : requests.PreparedRequest
            The PreparedRequest being sent.

        Returns
        -------
        requests.Response
            The Respone of the request.
        """
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)


class SessionFactory:
    """Class for generating pydov configured requests Sessions. They are used
    to send HTTP requests using our user-agent and with added retry-logic.

    One global session is generated for all requests, and additionally one
    session is generated per thread executing XML requests in parallel.
    """
    @staticmethod
    def get_session():
        """Request a new session.

        Returns
        -------
        requests.Session
            pydov configured requests Session.
        """
        session = requests.Session()

        session.headers.update(
            {'user-agent': 'pydov/{}'.format(pydov.__version__)})

        try:
            retry = urllib3.util.Retry(
                total=10, connect=10, read=10, redirect=5, backoff_factor=1,
                allowed_methods=set(['GET', 'POST']))
        except TypeError:
            retry = urllib3.util.Retry(
                total=10, connect=10, read=10, redirect=5, backoff_factor=1,
                method_whitelist=set(['GET', 'POST']))

        adapter = TimeoutHTTPAdapter(timeout=request_timeout,
                                     max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session


class LocalSessionThreadPool:
    """Thread pool of LocalSessionThreads used to perform XML I/O operations
    in parallel.
    """

    def __init__(self, workers=4):
        """Initialisation.

        Set up the pool and start all workers.

        Parameters
        ----------
        workers : int, optional
            Number of worker threads to use, defaults to 4.
        """
        self.workers = []
        self.input_queue = Queue(maxsize=100)
        self.result_queue = Queue()

        for i in range(workers):
            self.workers.append(
                LocalSessionThread(self.input_queue, self.result_queue))

        self._start()

    def _start(self):
        """Start all worker threads. """
        for w in self.workers:
            w.start()

    def stop(self):
        """Stop all worker threads. """
        for w in self.workers:
            w.stop()

    def execute(self, fn, args):
        """Execute the given function with its arguments in a worker thread.

        This will add the job to the queue and will not wait for the result.
        Use join() to retrieve the result.

        Parameters
        ----------
        fn : function
            Function to execute.
        args : tuple
            Arguments that will be passed to the function.
        """
        r = WorkerResult()
        self.input_queue.put((fn, args, r))
        self.result_queue.put(r)

    def join(self):
        """Wait for all the jobs to be executed and return the results of all
        jobs in a list.

        Returns
        -------
        list
            List of the result of all executed function in the order they were
            submitted.
        """
        self.input_queue.join()
        self.stop()

        results = []
        while not self.result_queue.empty():
            results.append(self.result_queue.get().get_result())
        return results


class WorkerResult:
    """Class for storing the result of a job execution in the result queue.

    This allows putting a result instance in the queue on job submission and
    fill in the result later when the job completes. This ensures the result
    output is in the same order as the jobs were submitted.
    """

    def __init__(self):
        """Initialisation. """
        self.result = None

    def set_result(self, value):
        """Set the result of this job.

        Parameters
        ----------
        value : any
            The result of the execution of the job.
        """
        self.result = value

    def get_result(self):
        """Retrieve the result of this job.

        Returns
        -------
        any
            The result of the exectution of the job.
        """
        return self.result


class LocalSessionThread(Thread):
    """Worker thread using a local Session to execute functions. """

    def __init__(self, input_queue):
        """Initialisation.

        Bind to the input queue and create a Session.

        Parameters
        ----------
        input_queue : queue.Queue
            Queue to poll for input, this should be in the form of a tuple with
            3 items: function to call, list with arguments and WorkerResult
            instance to store the output. The list with arguments will be
            automatically extended with the local Session instance.
        """
        super().__init__()
        self.input_queue = input_queue

        self.stopping = False
        self.session = SessionFactory.get_session()

    def stop(self):
        """Stop the worker thread at the next occasion. This can take up to
        500 ms. """
        self.stopping = True

    def run(self):
        """Executed while the thread is running. This is called implicitly
        when starting the thread. """
        while not self.stopping:
            try:
                fn, args, r = self.input_queue.get(timeout=0.5)
                args = list(args)
                args.append(self.session)
                result = fn(*args)
                r.set_result(result)
                self.input_queue.task_done()
            except Empty:
                pass
