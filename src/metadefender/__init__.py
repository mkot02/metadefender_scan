from metadefender.app import MetadefenderResultParser, MetadefenderScanner

__version = "0.1.0"


def buildFileList(files, includes=None, excludes=None, recursive=None):
    import os

    files = files if isinstance(files, list) else [files]

    result_list = []
    for fil in files:
        # Discard files which don't exists
        if not os.path.exists(fil):
            continue

        if os.path.isdir(fil):
            # Extend result list with file lists (2nd element of tuple)
            # of this this directory and all subdirectories
            for walk_step in os.walk(fil):
                dir_file_list = [os.path.join(walk_step[0], f) for f in walk_step[2]]
                result_list.extend(dir_file_list)

                # Break after first iteration if recursive flag is not set to
                # list only files in directory not subdirectories
                if fil == walk_step[0] and not recursive:
                    break
        else:
            result_list.append(fil)

    # Apply filters and return
    if includes is not None and excludes is not None:
        raise ValueError("Includes and excludes cannot be specified at the same time")
    elif includes is not None:
        ext_list = tuple(["." + ext for ext in includes.split(",")])
        return [os.path.abspath(f) for f in result_list if f.endswith(ext_list)]
    elif excludes is not None:
        ext_list = tuple(["." + ext for ext in excludes.split(",")])
        return [os.path.abspath(f) for f in result_list if not f.endswith(ext_list)]
    else:
        return result_list


def main():
    import argparse
    import multiprocessing.dummy as multiprocessing

    parser = argparse.ArgumentParser(prog="metadefender_scan", add_help=False)
    group_file = parser.add_argument_group(title="File(s) settgins")
    group_file.add_argument("files", nargs="+")
    group_file.add_argument(
        "-r",
        "--recursive",
        help="Scan files from subdirectories if specified file is a directory itself",
        action="store_true",
    )
    group_filter = group_file.add_mutually_exclusive_group()
    group_filter.add_argument(
        "-i",
        "--extension-include",
        dest="includes",
        help="Specify comma-separated list of file extensions. Only files with specified extensions will be scanned",
    )
    group_filter.add_argument(
        "-e",
        "--extension-exclude",
        dest="excludes",
        help="Specify comma-separated list of file extensions. Files with specified extensions will not be scanned",
    )
    group_file.add_argument(
        "-o",
        "--output",
        help="Specify file which scanning results will be saved to",
    )
    group_server = parser.add_argument_group(title="Server settgins")
    group_server.add_argument(
        "-s",
        "--server",
        help="Specify URL of MetaDefender server",
    )
    group_auth = group_file.add_mutually_exclusive_group()
    group_auth.add_argument(
        "-k", "--api-key", dest="apikey", help="Specify API Key for MetaDefender server"
    )
    group_server.add_argument(
        "--force",
        type=bool,
        default=False,
        help="Send file to server even if there is cached result for this file",
    )
    group_other = parser.add_argument_group(title="Other settgins")
    group_other.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=5,
        help="Specify how many concurrent jobs should be started. Works only if scanning directory",
    )
    group_other.add_argument(
        "-h", "--help", help="Print this help message", action="help"
    )
    group_other.add_argument(
        "-v",
        "--verbose",
        help="Print what is currently being done to STDOUT",
        action="store_true",
    )
    cli_args = parser.parse_args()

    # Perform scanning
    if cli_args.verbose:
        print("Building list of files to process")
    file_list = buildFileList(
        cli_args.files, cli_args.includes, cli_args.excludes, cli_args.recursive
    )
    if cli_args.verbose:
        print("Discovered {0} files to process".format(len(file_list)))

    if len(file_list) == 0:
        raise SystemExit("No files to process")

    # Create objects
    scanner = MetadefenderScanner(cli_args.server, cli_args.apikey, cli_args.force)
    result_parser = MetadefenderResultParser(cli_args.server)
    process_pool = multiprocessing.Pool(processes=cli_args.jobs)

    result_map = process_pool.map(scanner.scan_file, file_list)

    # Update result_parser with results
    for filename, result in result_map:
        result_parser.update(result)
    else:
        results = result_parser.dump_yaml()

    # Deal with the results
    if cli_args.output:
        with open(cli_args.output, "w") as fd:
            fd.write(results)
    else:
        print(results)

    if cli_args.verbose:
        print("Finished")


if __name__ == "__main__":
    main()
