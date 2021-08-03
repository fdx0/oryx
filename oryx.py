#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
@File    :  oryx.py
@Time    :  2021/03/25 15:30:00
@Author  :  Aaron Louks
@Version :  1.0
@Contact :  aaron@zoatrope.com
@License :  MIT
@Desc    :  A script for managing multiprocess yara scans
'''

import argparse
import multiprocessing
import concurrent.futures
import subprocess
import logging
import asyncio
import os
import sys
import time

logger = multiprocessing.get_logger()
logger.setLevel(logging.DEBUG)
if not os.path.exists('logs/scanner.log'):
    os.makedirs('logs')
    open('logs/scanner.log', 'w+')
fh = logging.FileHandler(f"logs/scanner.log")
formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
fh.setFormatter(formatter)
logger.addHandler(fh)

class Oryx(multiprocessing.Process):

    def __init__(self, task_queue, result_queue, mode, rules):
        multiprocessing.Process.__init__(self)
        self.task_queue = task_queue
        self.result_queue = result_queue
        self.mode = mode
        self.rules = rules

    def mycallback(data):
        logger.info(f'MATCH {data}')
        return yara.CALLBACK_CONTINUE

    async def async_process(self, path: str) -> str:
        logger.debug(f'{self.name} processing_path {path} with rules {self.rules}')

        # Actually launch the yara process
        res = os.system(f"yara -fws '{self.rules}' '{path}' >> results.txt 2>&1")

        if not res:
            return f'{path} scan failed'

        return f'{path} scan succeeded'

    async def async_spawner(self, paths: list) -> None:
        logger.info(f'{self.name} session for {len(paths)} paths')
        results = []
        tasks = []

        for p in paths:
            logger.info(f'Working on path {p}')
            tasks.append(self.async_process(path=p))
        results = await asyncio.gather(*tasks)

        # send result status
        for r in results:
            self.result_queue.put(r)

    def sync_process(self, paths: list) -> None:
        for p in paths:
            logger.debug(f'{self.name} processing_path {p}')
            resp = os.system(f"yara -fws '{self.rules}' '{p}' >> results.txt 2>&1")
            self.result_queue.put(f'{p} scan complete')

    def check_battery(self) -> str:
        if sys.platform == "linux" or sys.platform == "linux2":
            command = "upower -i $(upower -e | grep BAT) | grep --color=never -E percentage|xargs|cut -d' ' -f2|sed s/%//"
        elif sys.platform == "darwin":
            command = 'pmset -g batt | grep -Eo "\d+%" | cut -d% -f1'
        get_batterydata = subprocess.Popen(["/bin/bash", "-c", command], stdout=subprocess.PIPE)
        return get_batterydata.communicate()[0].decode("utf-8").replace("\n", "")

    def run(self):
        pname = self.name
        paths = []
        low = 0

        # Get all tasks
        while True:
            #charge = int(self.check_battery())
            #logger.info(f'Current Charge: {charge}')
            #TODO: Need to work on battery calculation frequency and other performance tuning parameters here
            charge = 66
            if charge > 20 and low == 0:
                t = self.task_queue.get()
                if t is None:
                    logger.debug(f'{pname} Received all found paths')
                    break
                paths.append(t)
                self.task_queue.task_done()
            elif charge <= 20:
                low = 1
                logger.debug(f'{pname} Sleeping for 10 seconds')
                time.sleep(10)

        logger.info(f'{pname} processing {self.mode} {len(paths)} paths')

        # Do sync or async processing
        if self.mode == "async":
            asyncio.run(self.async_spawner(paths))
        else:
           self.sync_process(paths)

        # Respond to None received in task_queue
        self.task_queue.task_done()


def parse_clargs():
    ''' Command line argument parser. '''
    mparser = argparse.ArgumentParser(
        description='A process manager for yara scanning.')
    mparser.add_argument('-r',
                         '--rules',
                         action='store',
                         type=str,
                         help='yara rules path')
    mparser.add_argument('-p',
                         '--path',
                         action='store',
                         type=str,
                         help='scanning path')
    mparser.add_argument('-m',
                         '--mode',
                         action='store',
                         default='sync',
                         choices=['sync', 'async'],
                         help='task processing mode')
    mparser.add_argument('-t',
                         '--threads',
                         action='store',
                         type=int,
                         default=1,
                         help='multiprocessing thread count')

    return mparser.parse_args()


def main():
    '''Main entry function'''

    # Get cli arguments
    args = parse_clargs()

    # Gather threads argument if available
    if (args.threads > 1):
        threads = args.threads
    else:
    # Otherwise, use total amount of cpus minus two
        threads = multiprocessing.cpu_count() - 2
    # Limit max threads to total cpu count
    if threads > multiprocessing.cpu_count():
        threads = multiprocessing.cpu_count()

    # Task queue is used to send the directory paths to processes
    # Result queue is used to get the result from processes
    tq = multiprocessing.JoinableQueue()   # task queue
    rq = multiprocessing.Queue()         # result queue

    logger.info(f'Spawning {threads} processes...')

    oryx = [Oryx(tq, rq, args.mode, args.rules) for i in range(threads)]

    futures = [] # To store our futures
    with concurrent.futures.ProcessPoolExecutor(threads) as executor:
        for o in oryx:
            new_future = executor.submit(
                o.start(), # Execute function
            )
            futures.append(new_future)

        concurrent.futures.wait(futures)

    if args.path:
        path = args.path
    else:
        path = '/'
    # Iterate through a path and add the directories to the queue
    dir_path = os.path.realpath(path)
    for root, dirs, files in os.walk(dir_path):
        for d in dirs:
            logger.info(f'adding path: '+root+'/'+str(d))
            tq.put(root+'/'+str(d))

    # enqueue None in task_queue to indicate completion
    for _ in range(threads):
        tq.put(None)

    # Block until all items in the queue have been fetched and processed.
    # When the count of unfinished tasks drops to zero, join() unblocks.
    tq.join()


if __name__ == '__main__':
    start = time.perf_counter()
    main()
    end = time.perf_counter() - start
    print(f"Scan finished in {end:0.2f} seconds.")


'''

usage: oryx.py [-h] [-m {sync,async}] [-t THREADS] [-p PATH]

A process manager for yara scanning.

optional arguments:
  -h, --help            show this help message and exit
  -r RULES, --rules RULES
                        rules path
  -p PATH, --path PATH  scanning path
  -m {sync,async}, --mode {sync,async}
                        task processing mode
  -t THREADS, --threads THREADS
                        multiprocessing thread count

=====================================
Example Usage

./oryx.py -r /path/to/rules -p /path/to/directory -m async

./oryx.py -r /path/to/rules -p /path/to/directory -m async -t 7

./oryx.py -r sample_rules/Emotet_and_Friends.yara -p /path/to/directory -m async


'''
