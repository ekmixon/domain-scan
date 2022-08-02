from utils import utils


def write_rows(rows, domain, base_domain, scanner, csv_writer, meta=None):

    # If we didn't get any info, we'll still output information about why the scan failed.
    if rows is None:
        empty_row = [None] * len(scanner.headers)
        rows = [empty_row]

    # Always output Domain and Base Domain.
    standard_prefix = [
        domain,
        base_domain,
    ]

    # If requested, add local and Lambda scan data.
    meta_fields = []
    if meta:
        meta_fields.extend(
            (
                " ".join(meta.get('errors', [])),
                utils.utc_timestamp(meta.get("start_time")),
                utils.utc_timestamp(meta.get("end_time")),
                utils.just_microseconds(meta.get("duration")),
            )
        )

        if meta.get("lambda") is not None:
            meta_fields.extend(
                (
                    meta['lambda'].get('request_id'),
                    meta['lambda'].get('log_group_name'),
                    meta['lambda'].get('log_stream_name'),
                    utils.utc_timestamp(meta['lambda'].get('start_time')),
                    utils.utc_timestamp(meta['lambda'].get('end_time')),
                    meta['lambda'].get('memory_limit'),
                    utils.just_microseconds(
                        meta['lambda'].get('measured_duration')
                    ),
                )
            )

    # Write out prefix, scan data, and meta scan data.
    for row in rows:
        csv_writer.writerow(standard_prefix + row + meta_fields)
