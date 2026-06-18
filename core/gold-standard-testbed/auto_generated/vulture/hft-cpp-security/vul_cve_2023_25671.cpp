// Vulnerable: VUL-CVE-2023-25671
":graphdef_import",
        ":load_proto",
        "//tensorflow/core:ops",  # Ops need to be registered for import.
        "//tensorflow/core/ir:Dialect",
// --- tfg-translate.cc ---
#include "mlir/Tools/mlir-translate/MlirTranslateMain.h"  // from @llvm-project
#include "mlir/Tools/mlir-translate/Translation.h"  // from @llvm-project
#include "tensorflow/core/ir/dialect.h"
#include "tensorflow/core/ir/importexport/graphdef_export.h"
...
int main(int argc, char **argv) {
  mlir::registerAsmPrinterCLOptions();
  return failed(
      mlir::mlirTranslateMain(argc, argv, "Graph(Def)<->TFG Translation Tool"));
