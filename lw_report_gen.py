import sys
import os
import shutil
import subprocess
import tempfile
import logzero
import datetime
import traceback
from logzero import logger
from modules.process_args import get_validated_arguments, pre_process_args
from modules.utils import get_available_reports
from modules.utils import alert_new_release
from modules.reportgen import ReportGen  # do not remove, needed by pyinstaller
from modules.spinner import Spinner


def _find_chrome():
    """Return path to Chrome/Chromium executable, or None if not found."""
    candidates = [
        # macOS
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '/Applications/Chromium.app/Contents/MacOS/Chromium',
        # Linux
        'google-chrome', 'google-chrome-stable', 'chromium-browser', 'chromium',
        # Windows
        r'C:\Program Files\Google\Chrome\Application\chrome.exe',
        r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
        found = shutil.which(c)
        if found:
            return found
    return None


def _html_to_pdf_chrome(html_string, output_path):
    """Write PDF via Chrome headless. Returns True on success."""
    chrome = _find_chrome()
    if not chrome:
        return False
    with tempfile.NamedTemporaryFile(suffix='.html', mode='w', encoding='utf-8', delete=False) as f:
        f.write(html_string)
        tmp_html = f.name
    try:
        result = subprocess.run(
            [
                chrome,
                '--headless=new',
                '--no-sandbox',
                '--disable-gpu',
                '--disable-extensions',
                '--run-all-compositor-stages-before-draw',
                f'--print-to-pdf={os.path.abspath(output_path)}',
                '--no-pdf-header-footer',
                '--paper-width=16.54',   # A3 landscape (inches)
                '--paper-height=11.69',
                f'file://{tmp_html}',
            ],
            capture_output=True, timeout=120
        )
        return result.returncode == 0
    finally:
        os.unlink(tmp_html)


def _html_to_pdf_weasyprint(html_string, output_path, basedir):
    """Write PDF via WeasyPrint. Returns True on success."""
    from weasyprint import HTML
    from weasyprint.text.fonts import FontConfiguration
    import logging as log
    log.getLogger('weasyprint').addHandler(log.FileHandler('weasyprint.log'))
    fc = FontConfiguration()
    HTML(string=html_string, base_url=basedir).write_pdf(output_path, font_config=fc)
    return True


def main():

    # Get the base directory where this script is running from
    # Required for Pyinstaller as it temporarily extracts all files to a temp folder before running
    if getattr(sys, 'frozen', False):
        basedir = sys._MEIPASS
    else:
        basedir = os.path.dirname(os.path.abspath(__file__))

    # Set up default logging level
    logzero.loglevel(logzero.WARNING)
    # Setup up log file, always write verbose logs
    logzero.logfile('lw_report_gen.log', loglevel=logzero.DEBUG)

    # Dynamically import report classes from "modules/reports" subdirectory
    available_reports: list = get_available_reports(basedir)
    if len(available_reports) == 0:
        logger.debug('No available reports to run. You should not get this error since there is a default report.')
        logger.debug('If you are running from source, did you delete the contents of modules/reports? ')
        logger.debug('If you are running the binary, please report this error on the github page:')
        logger.debug('https://github.com/lacework/extensible-reporting')
        sys.exit()
    # Get command line args and process them
    args = get_validated_arguments()
    pre_processed_args = pre_process_args(args, available_reports)

    if args.gui:
        # Bring up the GUI interface
        from modules.gui_main import ExtensibleReportingGUI
        report_gui = ExtensibleReportingGUI(args, pre_processed_args, available_reports, basedir)
        report_gui.exec()
    else:
        # Execute the selected report from command line (no GUI)
        custom_logo = args.logo if args.logo else None
        spinner = Spinner('Generating Cloud Security Posture')
        spinner.start()
        try:
            if args.report_format == "HTML":
                report_generator = pre_processed_args['report_to_run'](basedir, use_cache=args.cache_data, api_key_file=pre_processed_args['api_key_file'])
                report = report_generator.generate(args.customer,
                                                args.author,
                                                vulns_start_time=pre_processed_args['vulns_start_time'],
                                                vulns_end_time=pre_processed_args['vulns_end_time'],
                                                alerts_start_time=pre_processed_args['alerts_start_time'],
                                                alerts_end_time=pre_processed_args['alerts_end_time'],
                                                ciem_threshold=args.ciem_threshold,
                                                compliance_framework=args.compliance_framework,
                                                custom_logo=custom_logo,
                                                progress_cb=spinner.update,
                                                )
            elif args.report_format == "PDF":
                report_generator = pre_processed_args['report_to_run'](basedir, use_cache=args.cache_data, api_key_file=pre_processed_args['api_key_file'], graph_scale=1.4)
                report = report_generator.generate(args.customer,
                                                args.author,
                                                vulns_start_time=pre_processed_args['vulns_start_time'],
                                                vulns_end_time=pre_processed_args['vulns_end_time'],
                                                alerts_start_time=pre_processed_args['alerts_start_time'],
                                                alerts_end_time=pre_processed_args['alerts_end_time'],
                                                ciem_threshold=args.ciem_threshold,
                                                compliance_framework=args.compliance_framework,
                                                custom_logo=custom_logo,
                                                pagesize='a2',
                                                pdf=True,
                                                progress_cb=spinner.update,
                                                )
        except Exception as e:
            spinner.stop(success=False)
            logger.error(f"Report generation failed for '{args.report}'. Check what's available with '--list-reports'.")
            logger.error(str(e))
            logger.error(traceback.format_exc())
            sys.exit()
        spinner.stop(success=True)

        # Generate a filename if one was not specified
        if not args.report_path:
            report_file_name = f'{args.customer}_RCA_{datetime.datetime.now().strftime("%Y%m%d")}'
        else:
            report_file_name = args.report_path

        if args.report_format == "HTML":
            report_file_name += ".html"
            # Write out the report file
            logger.info(f'Writing report to {report_file_name}')
            try:
                with open(str(report_file_name), 'w') as file:
                    file.write(report)
            except Exception as e:
                logger.error(f'Failed writing report file {report_file_name}: {str(e)}')
                sys.exit()
        elif args.report_format == "PDF":
            report_file_name += ".pdf"
            logger.info(f'Writing report to {report_file_name}')
            try:
                if _find_chrome():
                    logger.info('PDF backend: Chrome headless')
                    ok = _html_to_pdf_chrome(report, report_file_name)
                    if not ok:
                        raise RuntimeError('Chrome headless exited with non-zero status')
                else:
                    logger.warning('Chrome not found — falling back to WeasyPrint')
                    _html_to_pdf_weasyprint(report, report_file_name, basedir)
            except Exception as e:
                logger.error(f'Failed writing report file {report_file_name}: {str(e)}')
                sys.exit()    

if __name__ == "__main__":
    main()
