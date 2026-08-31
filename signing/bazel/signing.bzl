def signed_binary(name, key, signing_method = "openssl", cert = None, chain = None, **kwargs):
    """Build a cc_binary and emit a portable detached signature envelope beside it."""
    if signing_method not in ["openssl", "pki"]:
        fail("signing_method must be 'openssl' or 'pki'")
    if signing_method == "pki" and (cert == None or chain == None):
        fail("PKI signing requires cert and chain labels")

    native.cc_binary(name = name, **kwargs)
    signing_inputs = [":" + name, key]
    command = "$(location //signing:sign_artifact.py) --method {method} --key $(location {key}) --in $(location :{name}) --out $@".format(
        method = signing_method,
        key = key,
        name = name,
    )
    if cert:
        signing_inputs.append(cert)
        command += " --cert $(location {cert})".format(cert = cert)
    if chain:
        signing_inputs.append(chain)
        command += " --chain $(location {chain})".format(chain = chain)
    native.genrule(
        name = name + "_signature",
        srcs = signing_inputs,
        outs = [name + ".sig"],
        cmd = command,
        tools = ["//signing:sign_artifact.py"],
    )