"""Minimal action that mirrors module_registry's use of StarlarkModuleInfo.src."""

load("@build_stack_rules_proto//rules:starlark_module.bzl", "StarlarkModuleInfo")

def _production_fetch_compile_impl(ctx):
    source = ctx.attr.src[StarlarkModuleInfo]
    output = ctx.actions.declare_file(ctx.label.name + ".documentationinfo.pb.gz")
    args = ctx.actions.args()
    args.add("--output_file", output)
    args.add("--java_interpreter_file", ctx.attr.java_interpreter)
    args.add("--server_jar_file", ctx.file.server_jar)
    args.add("--log_file", "/tmp/bcr-production-fetch-bzlcompiler.log")
    args.add("--bzl_file=proof|%s|%s" % (source.label, source.src.path))
    args.add("--module_dep=proof:NONE")
    args.add(source.src)
    ctx.actions.run(
        executable = ctx.file.compiler,
        arguments = [args],
        inputs = [source.src, ctx.file.server_jar],
        outputs = [output],
        mnemonic = "CompileProductionFetchedBzl",
        progress_message = "Compiling the Bazel-fetched Starlark file %{label}",
    )
    return [DefaultInfo(files = depset([output]))]

production_fetch_compile = rule(
    implementation = _production_fetch_compile_impl,
    attrs = {
        "compiler": attr.label(allow_single_file = True, mandatory = True),
        "java_interpreter": attr.string(mandatory = True),
        "server_jar": attr.label(allow_single_file = True, mandatory = True),
        "src": attr.label(mandatory = True, providers = [StarlarkModuleInfo]),
    },
)
