import subprocess
import os
import json
import shlex
import logging
import urllib.parse
from celery import Celery
from .tools.radare2_runner import run_radare2
from .tools.floss_runner import run_floss

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

GHIDRA_INSTALL_DIR = "/opt/ghidra_11.0.1_PUBLIC"  # Update if your version is different

# Celery configuration
app = Celery('analyzer',
                    broker='redis://redis:6379/0',  # Redis broker URL
                    backend='redis://redis:6379/0')  # Redis backend URL

def route_task(name, *args, **kwargs):
    if name == 'backend.analyzer.analyze_file_task' or name == 'backend.analyzer.analyze_url_task':
        return {'queue': 'high_priority_queue'}
    elif name == 'backend.analyzer.run_ghidra_headless':
        return {'queue': 'low_priority_queue'}
    else:
        return {'queue': 'medium_priority_queue'}

app.conf.task_routes = (route_task,)

@app.task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={'max_retries': 3})
def run_tool_task(self, tool_name, command, timeout=60):
    """
    Runs a given tool with a timeout.  Using Celery task.
    """
    logging.info(f"Running {tool_name} with command: {' '.join(command)}")
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=timeout)

        returncode = process.returncode

        if returncode != 0:
            logging.error(f"{tool_name} failed with error: {stderr}")
            return {
                "status": "error",
                "tool_name": tool_name,
                "command": command,
                "stdout": stdout,
                "stderr": stderr,
                "returncode": returncode,
                "error": f"{tool_name} failed with error: {stderr}"
            }

        logging.info(f"{tool_name} completed successfully.")
        return {
            "status": "success",
            "tool_name": tool_name,
            "command": command,
            "stdout": stdout,
            "stderr": stderr,
            "returncode": returncode,
            "error": None
        }

    except subprocess.TimeoutExpired:
        process.kill()
        logging.error(f"{tool_name} timed out.")
        return {
            "status": "error",
            "tool_name": tool_name,
            "command": command,
            "stdout": "",
            "stderr": "",
            "returncode": None,
            "error": f"{tool_name} timed out."
        }
    except FileNotFoundError:
        logging.error(f"{tool_name} not found. Ensure it is installed and in the PATH.")
        return {
            "status": "error",
            "tool_name": tool_name,
            "command": command,
            "stdout": "",
            "stderr": "",
            "returncode": None,
            "error": f"{tool_name} not found. Ensure it is installed and in the PATH."
        }
    except Exception as e:
        logging.exception(f"{tool_name} encountered an unexpected error.")
        return {
            "status": "error",
            "tool_name": tool_name,
            "command": command,
            "stdout": "",
            "stderr": "",
            "returncode": None,
            "error": f"{tool_name} encountered an unexpected error: {str(e)}"
        }

@app.task(time_limit=600)
def run_ghidra_headless(file_path):
    """
    Runs Ghidra in headless mode to analyze the file.
    """
    analyze_script = os.path.join(os.getcwd(), "backend", "tools", "ghidra_analyzer.py")
    command = [
        f"{GHIDRA_INSTALL_DIR}/support/analyzeHeadless",
        os.getcwd(),  # Project directory (current working directory)
        "GhidraProject",  # Project name
        "-import",
        file_path,
        "-scriptPath",
        os.path.dirname(analyze_script),
        "-postScript",
        os.path.basename(analyze_script),
        "-noanalysis"  # Skip default analysis to speed up
    ]
    return run_tool_task("Ghidra", command, timeout=300)  # Increased timeout for Ghidra

@app.task(time_limit=120)
def run_binwalk(file_path):
    """
    Runs binwalk to scan the file for embedded files and executable code.
    """
    command = ["binwalk", file_path]
    return run_tool_task("Binwalk", command)

@app.task(time_limit=120)
def run_yara(file_path):
    """
    Runs yara to scan the file for malware signatures.
    """
    command = ["yara", "/yara/rules/", file_path]
    return run_tool_task("Yara", command)

@app.task(time_limit=60)
def run_upx(file_path):
    """
    Runs UPX to check if the file is packed.
    """
    command = ["upx", "-t", file_path]
    return run_tool_task("UPX", command)

@app.task(time_limit=60)
def run_pefile(file_path):
    """
    Runs pefile to extract information about the file.
    """
    try:
        import pefile
        pe = pefile.PE(file_path)
        return {
            "status": "success",
            "tool_name": "PEfile",
            "output": str(pe.dump_info()),
            "error": None
        }
    except Exception as e:
        return {
            "status": "error",
            "tool_name": "PEfile",
            "output": None,
            "error": str(e)
        }

@app.task(time_limit=60)
def run_lief(file_path):
    """
    Runs lief to extract information about the file.
    """
    try:
        import lief
        binary = lief.parse(file_path)
        return {
            "status": "success",
            "tool_name": "LIEF",
            "output": str(binary),
            "error": None
        }
    except Exception as e:
        return {
            "status": "error",
            "tool_name": "LIEF",
            "output": None,
            "error": str(e)
        }

@app.task(time_limit=60)
def run_capstone(file_path):
    """
    Runs capstone to disassemble the file.
    """
    try:
        import capstone
        # Open the file in binary read mode
        with open(file_path, 'rb') as f:
            code = f.read()
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        output = ""
        for i in md.disasm(code, 0x1000):
            output += f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}\n"
        return {
            "status": "success",
            "tool_name": "Capstone",
            "output": output,
            "error": None
        }
    except Exception as e:
        return {
            "status": "error",
            "tool_name": "Capstone",
            "output": None,
            "error": str(e)
        }

@app.task(time_limit=60)
def run_strings(file_path):
    """
    Runs strings to extract printable strings from the file.
    """
    command = ["strings", file_path]
    return run_tool_task("Strings", command)

@app.task(time_limit=60)
def run_ssdeep(file_path):
    """
    Runs ssdeep to compute the fuzzy hash of the file.
    """
    command = ["ssdeep", file_path]
    return run_tool_task("Ssdeep", command)

@app.task(time_limit=60)
def run_exiftool(file_path):
    """
    Runs exiftool to extract metadata from the file.
    """
    command = ["exiftool", file_path]
    return run_tool_task("Exiftool", command)

@app.task(time_limit=60)
def run_trid(file_path):
    """
    Runs TrID to identify file types.
    """
    command = ["trid", file_path]
    return run_tool_task("TrID", command)

@app.task(time_limit=120)
def run_ffprobe(file_path):
    """
    Runs FFprobe to extract multimedia metadata.
    """
    command = ["ffprobe", "-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", file_path]
    return run_tool_task("FFprobe", command)

@app.task(time_limit=60)
def run_pdfid(file_path):
    """
    Runs pdfid to analyze PDF files.
    """
    command = ["pdfid", file_path]
    return run_tool_task("PDFiD", command)

@app.task(time_limit=120)
def run_pdfparser(file_path):
    """
    Runs pdfparser to extract information from PDF files.
    """
    command = ["pdfparser", "-o", file_path]
    return run_tool_task("PDFParser", command)

@app.task(time_limit=120)
def run_olevba(file_path):
    """
    Runs olevba to analyze VBA macros in Office files.
    """
    command = ["olevba", file_path]
    return run_tool_task("Olevba", command)

@app.task(time_limit=120)
def run_nmap(url):
    """
    Runs nmap to scan the URL for open ports and services.
    """
    command = ["nmap", url]
    return run_tool_task("Nmap", command)

@app.task(time_limit=300)
def run_nikto(url):
    """
    Runs Nikto to scan the URL for vulnerabilities.
    """
    command = ["nikto", "-h", url]
    return run_tool_task("Nikto", command)

@app.task(time_limit=300)
def run_dirb(url):
    """
    Runs Dirb to brute force directories and files on the URL.
    """
    command = ["dirb", url]
    return run_tool_task("Dirb", command)

@app.task(time_limit=120)
def run_whatweb(url):
    """
    Runs WhatWeb to identify technologies used on the URL.
    """
    command = ["whatweb", url]
    return run_tool_task("WhatWeb", command)

@app.task(time_limit=60)
def run_curl(url):
    """
    Runs curl to fetch the content of the URL.
    """
    command = ["curl", url]
    return run_tool_task("Curl", command)

@app.task(time_limit=120)
def run_wafw00f(url):
    """
    Runs WAFW00F to identify Web Application Firewalls.
    """
    command = ["wafw00f", url]
    return run_tool_task("WAFW00F", command)

@app.task(time_limit=300)
def run_testssl(url):
    """
    Runs testssl.sh to check SSL/TLS encryption.
    """
    command = ["testssl.sh", url]
    return run_tool_task("Testssl", command)

@app.task(time_limit=300)
def run_sslyze(url):
    """
    Runs SSLyze to analyze the SSL configuration of the URL.
    """
    command = ["sslyze", "--regular", url]
    return run_tool_task("Sslyze", command)

@app.task(time_limit=600)
def run_theharvester(url):
    """
    Runs theHarvester to gather emails, subdomains, hosts, employee names, open ports and banners from different public sources.
    """
    command = ["theharvester", "-d", url, "-l", "500", "-b", "all"]
    return run_tool_task("TheHarvester", command)

@app.task(time_limit=120)
def run_dmitry(url):
    """
    Runs DMitry to gather as much information as possible about a host.
    """
    command = ["dmitry", "-winpe", url]
    return run_tool_task("DMitry", command)

@app.task(time_limit=300)
def run_fierce(url):
    """
    Runs Fierce to locate non-contiguous IP space and hostnames.
    """
    command = ["fierce", "-dns", url]
    return run_tool_task("Fierce", command)

@app.task(time_limit=300)
def run_dnsrecon(url):
    """
    Runs DNSRecon to perform DNS enumeration.
    """
    command = ["dnsrecon", "-d", url]
    return run_tool_task("DNSRecon", command)

@app.task(time_limit=600)
def run_metagoofil(url):
    """
    Runs Metagoofil to extract metadata from public documents.
    """
    command = ["metagoofil", "-d", url, "-t", "pdf,doc,xls,ppt,docx,xlsx,pptx", "-l", "200", "-n", "50", "-o", "results"]
    return run_tool_task("Metagoofil", command)

@app.task
def analyze_file_task(path, tools=None):
    results = {}

    if tools is None:
        tools = ["radare2", "floss", "ghidra", "binwalk", "yara", "upx", "pefile", "lief", "capstone", "strings", "ssdeep", "exiftool", "trid", "ffprobe", "pdfid", "pdfparser", "olevba"]

    if "radare2" in tools:
        try:
            results["radare2"] = run_radare2(path)
        except Exception as e:
            results["radare2"] = {"status": "error", "error": str(e)}

    if "floss" in tools:
        try:
            results["floss"] = run_floss(path)
        except Exception as e:
            results["floss"] = {"status": "error", "error": str(e)}

    if "ghidra" in tools:
        try:
            ghidra_result = run_ghidra_headless(path)
            results["ghidra"] = ghidra_result
        except Exception as e:
            results["ghidra"] = {"status": "error", "error": str(e)}

    if "binwalk" in tools:
        try:
            binwalk_result = run_binwalk(path) # Removed .get()
            results["binwalk"] = binwalk_result
        except Exception as e:
            results["binwalk"] = {"status": "error", "error": str(e)}

    if "yara" in tools:
        try:
            results["yara"] = run_yara(path)
        except Exception as e:
            results["yara"] = {"status": "error", "error": str(e)}

    if "upx" in tools:
        try:
            results["upx"] = run_upx(path)
        except Exception as e:
            results["upx"] = {"status": "error", "error": str(e)}

    if "pefile" in tools:
        try:
            results["pefile"] = run_pefile(path)
        except Exception as e:
            results["pefile"] = {"status": "error", "error": str(e)}

    if "lief" in tools:
        try:
            results["lief"] = run_lief(path)
        except Exception as e:
            results["lief"] = {"status": "error", "error": str(e)}

    if "capstone" in tools:
        try:
            results["capstone"] = run_capstone(path)
        except Exception as e:
            results["capstone"] = {"status": "error", "error": str(e)}

    if "strings" in tools:
        try:
            results["strings"] = run_strings(path)
        except Exception as e:
            results["strings"] = {"status": "error", "error": str(e)}

    if "ssdeep" in tools:
        try:
            results["ssdeep"] = run_ssdeep(path)
        except Exception as e:
            results["ssdeep"] = {"status": "error", "error": str(e)}

    if "exiftool" in tools:
        try:
            results["exiftool"] = run_exiftool(path)
        except Exception as e:
            results["exiftool"] = {"status": "error", "error": str(e)}

    if "trid" in tools:
        try:
            results["trid"] = run_trid(path)
        except Exception as e:
            results["trid"] = {"status": "error", "error": str(e)}

    if "ffprobe" in tools:
        try:
            results["ffprobe"] = run_ffprobe(path)
        except Exception as e:
            results["ffprobe"] = {"status": "error", "error": str(e)}

    if "pdfid" in tools:
        try:
            results["pdfid"] = run_pdfid(path)
        except Exception as e:
            results["pdfid"] = {"status": "error", "error": str(e)}

    if "pdfparser" in tools:
        try:
            results["pdfparser"] = run_pdfparser(path)
        except Exception as e:
            results["pdfparser"] = {"status": "error", "error": str(e)}

    if "olevba" in tools:
        try:
            results["olevba"] = run_olevba(path)
        except Exception as e:
            results["olevba"] = {"status": "error", "error": str(e)}
    # Add more file analysis tools here
    return results

@app.task
def analyze_url_task(url, tools=None):
    results = {}

    if tools is None:
        tools = ["curl", "nmap", "nikto", "dirb", "whatweb", "wafw00f", "testssl", "sslyze", "theharvester", "dmitry", "fierce", "dnsrecon", "metagoofil"]

    if "curl" in tools:
        try:
            results["curl"] = run_curl(url)
        except Exception as e:
            results["curl"] = {"status": "error", "error": str(e)}

    if "nmap" in tools:
        try:
            results["nmap"] = run_nmap(url)
        except Exception as e:
            results["nmap"] = {"status": "error", "error": str(e)}

    if "nikto" in tools:
        try:
            results["nikto"] = run_nikto(url)
        except Exception as e:
            results["nikto"] = {"status": "error", "error": str(e)}

    if "dirb" in tools:
        try:
            results["dirb"] = run_dirb(url)
        except Exception as e:
            results["dirb"] = {"status": "error", "error": str(e)}

    if "whatweb" in tools:
        try:
            results["whatweb"] = run_whatweb(url)
        except Exception as e:
            results["whatweb"] = {"status": "error", "error": str(e)}

    if "wafw00f" in tools:
        try:
            results["wafw00f"] = run_wafw00f(url)
        except Exception as e:
            results["wafw00f"] = {"status": "error", "error": str(e)}

    if "testssl" in tools:
        try:
            results["testssl"] = run_testssl(url)
        except Exception as e:
            results["testssl"] = {"status": "error", "error": str(e)}

    if "sslyze" in tools:
        try:
            results["sslyze"] = run_sslyze(url)
        except Exception as e:
            results["sslyze"] = {"status": "error", "error": str(e)}

    if "theharvester" in tools:
        try:
            results["theharvester"] = run_theharvester(url)
        except Exception as e:
            results["theharvester"] = {"status": "error", "error": str(e)}

    if "dmitry" in tools:
        try:
            results["dmitry"] = run_dmitry(url)
        except Exception as e:
            results["dmitry"] = {"status": "error", "error": str(e)}

    if "fierce" in tools:
        try:
            results["fierce"] = run_fierce(url)
        except Exception as e:
            results["fierce"] = {"status": "error", "error": str(e)}

    if "dnsrecon" in tools:
        try:
            results["dnsrecon"] = run_dnsrecon(url)
        except Exception as e:
            results["dnsrecon"] = {"status": "error", "error": str(e)}

    if "metagoofil" in tools:
        try:
            results["metagoofil"] = run_metagoofil(url)
        except Exception as e:
            results["metagoofil"] = {"status": "error", "error": str(e)}
    # Add URL analysis tools here
    return results

def analyze_file(path, tools=None):
    """Kicks off file analysis task"""
    task = analyze_file_task.delay(path, tools)
    return task.id

def analyze_url(url, tools=None):
    """Kicks off url analysis task"""
    task = analyze_url_task.delay(url, tools)
    return task.id

def analyze(path, url, tools=None):
    """
    Main analysis function that orchestrates the tiered analysis process.
    """
    results = {}
    sandbox_available = False
    ai_model_available = False

    # 1. Initial Analysis
    results.update(initial_analysis(path, url))

    # 2. Deobfuscation/Unpacking (Conditional)
    if path and (results.get("is_packed") or results.get("is_obfuscated")):
        results.update(deobfuscation_analysis(path))

    # 3. Static Analysis
    results.update(static_analysis(path))

    # 4. Dynamic Analysis (Conditional - If Sandbox Available)
    if sandbox_available and results.get("suspicious"):
        results.update(dynamic_analysis(path))

    # 5. URL Analysis (Conditional)
    if url:
        results.update(url_analysis(url))

    # 6. AI-Powered Analysis (Conditional - If Available)
    if ai_model_available:
        results.update(ai_analysis(path, url))

    return results

def initial_analysis(path, url):
    """
    Performs initial analysis to identify file type and extract basic information.
    """
    results = {}

    if path:
        try:
            # Use 'file' command to identify file type
            command = shlex.split(f"file {path}")
            file_result = run_tool_task("file", command)
            results["file_type"] = file_result.get("stdout")

            # Use 'trid' to identify file type
            command = shlex.split(f"trid {path}")
            trid_result = run_tool_task("trid", command)
            results["trid_results"] = trid_result.get("stdout")

            # Use 'strings' to extract printable strings
            command = shlex.split(f"strings {path}")
            strings_result = run_tool_task("strings", command)
            results["strings"] = strings_result.get("stdout")

            # Use 'exiftool' to extract metadata
            command = shlex.split(f"exiftool {path}")
            exiftool_result = run_tool_task("exiftool", command)
            results["exiftool_metadata"] = exiftool_result.get("stdout")

        except Exception as e:
            logging.exception("Error during initial file analysis.")
            results["initial_analysis_error"] = str(e)

    elif url:
        try:
            # Use 'curl' to fetch content
            command = shlex.split(f"curl {url}")
            curl_result = run_tool_task("curl", command)
            results["url_content"] = curl_result.get("stdout")

            # Use 'whatweb' to identify technologies
            command = shlex.split(f"whatweb {url}")
            whatweb_result = run_tool_task("whatweb", command)
            results["whatweb_results"] = whatweb_result.get("stdout")

        except Exception as e:
            logging.exception("Error during initial URL analysis.")
            results["initial_analysis_error"] = str(e)

    return results
