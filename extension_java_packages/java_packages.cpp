/**
 *  Copyright (c) 2022-present, Uptycs, Inc.
 *  All rights reserved.
 *
 *  * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/system.h>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>

namespace osquery {
namespace tables {
QueryData genJavaPackages(QueryContext& context);
}
} // namespace osquery
using namespace osquery;
class JavaPackages : public TablePlugin {
 private:
  TableColumns columns() const {
    return {
        std::make_tuple("artifact_id", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("group_id", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("filename", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("version", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("description", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("size", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("path", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("directory", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("sha256", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("file", TEXT_TYPE, ColumnOptions::DEFAULT),
    };
  }

  TableRows generate(QueryContext& context) {
    QueryData results = osquery::tables::genJavaPackages(context);
    TableRows rows;
    for (auto& r : results) {
      auto insert_row = make_table_row();
      for (auto it : r) {
        insert_row[it.first] = it.second;
      }
      rows.push_back(insert_row);
    }
    return rows;
  }
};

REGISTER_EXTERNAL(JavaPackages, "table", "java_packages");

int main(int argc, char* argv[]) {
  osquery::Initializer runner(argc, argv, ToolType::EXTENSION);

  auto status = startExtension("java_packages", "0.0.1");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  // Finally wait for a signal / interrupt to shutdown.
  runner.waitForShutdown();
  return runner.shutdown(0);
}
