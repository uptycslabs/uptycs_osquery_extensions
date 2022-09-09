/**
 *  Copyright (c) 2022-present, Uptycs, Inc.
 *  All rights reserved.
 *
 *  * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <queue>
#include <iostream>
#include <fstream>
#include <cstdio>
#ifndef _WIN32
#include <unistd.h>
#include <fnmatch.h>
#endif

#include <zip.h>

#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>

#include <osquery/filesystem/filesystem.h>
#include <osquery/core/system.h>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/hashing/hashing.h>

const std::size_t STREAM_BYTES = 1024;

namespace fs = boost::filesystem;

namespace osquery {

FLAG(bool,
    java_packages_checksum,
    true, 
    "Whether to compute SHA-256 checksum for Java packages table. Default: false");

namespace tables {

typedef decltype(&zip_close) ZipDeleter;
typedef decltype(&zip_fclose) ZipFileDeleter;

std::unique_ptr<zip_t, ZipDeleter> zipOpen(const std::string& path) {
  int err = ZIP_ER_OK;
  zip_t* za = zip_open(path.c_str(), ZIP_RDONLY, &err);
  if (!za || err != ZIP_ER_OK) {
    std::cout  << "Error opening JAR file at: " << path << "Error = "<<err;
    return std::unique_ptr<zip_t, ZipDeleter>(nullptr, nullptr);
  }

  return std::unique_ptr<zip_t, ZipDeleter>(za, zip_close);
}

std::unique_ptr<zip_t, ZipDeleter> zipOpenFromSource(zip_source_t *src) {
  int err = ZIP_ER_OK;
  zip_t* za = zip_open_from_source(src, ZIP_RDONLY, (zip_error_t*)&err);
  if (!za || err != ZIP_ER_OK) {
    std::cout  << "Error opening inner JAR file";
    return std::unique_ptr<zip_t, ZipDeleter>(nullptr, nullptr);
  }

  return std::unique_ptr<zip_t, ZipDeleter>(za, zip_close);
}

std::unique_ptr<zip_file_t, ZipFileDeleter> zipFopenIndex(std::unique_ptr<zip_t, ZipDeleter>& za, int index) {
  zip_file_t* file = zip_fopen_index(za.get(), index, ZIP_RDONLY);
  if (!file) {
    std::cout  << "Error opening file within JAR";
    return std::unique_ptr<zip_file_t, ZipFileDeleter>(nullptr, nullptr);
  }

  return std::unique_ptr<zip_file_t, ZipFileDeleter>(file, zip_fclose);
}

void storeManifestVal(std::string& dest, const std::string& manifest_line, const std::string& key) {
  if (dest.length() > 0) {
    return;
  }

  size_t found = manifest_line.find(key);
  if (found != std::string::npos) {
    boost::algorithm::trim(dest = manifest_line.substr(found + key.length() + 1));
  }
}

void populateRow(Row& r, uint64_t size, const std::string& filename, const std::string& path) {
  r["size"] = BIGINT(size);
  r["filename"] = filename;
  r["path"] = path;
}

Row processManifestMF(std::unique_ptr<zip_file_t, ZipFileDeleter>& manifest,
                      zip_stat_t* stats,
                      const std::string& inner_path,
                      QueryData& results) {
  fs::path p = fs::path(std::string(stats->name));

  std::string buffer;
  buffer.resize(stats->size);
  zip_fread(manifest.get(), &buffer[0], stats->size);

  Row r;
  populateRow(r, stats->size, p.filename().string(), inner_path + "/" + p.parent_path().string());

  std::istringstream mf_in(buffer);
  buffer.clear();

  std::string line;
  while (std::getline(mf_in, line)) {
    if (line.empty()) {
      continue;
    }

    auto ch = line.at(0);
    if (ch == ' ' || ch == '#') {
      continue; // Skip comment and continuration lines
    }

    storeManifestVal(r["group_id"], line, "Implementation-Vendor-Id");
    storeManifestVal(r["artifact_id"], line, "Bundle-SymbolicName");
    storeManifestVal(r["description"], line, "Bundle-Description");
    storeManifestVal(r["version"], line, "Implementation-Version");
    storeManifestVal(r["bundle_version"], line, "Bundle-Version");
    storeManifestVal(r["auto_name"], line, "Automatic-Module-Name");
  }

  // Try using the bundle version if we didn't find the implementation version
  if (r["version"].empty()) {
    r["version"] = std::move(r["bundle_version"]);
  }

  // Strip anything after a space in the version (some packages include git hashes after the version number)
  r["version"].resize(std::min(r["version"].find(" "), r["version"].size()));

  // Try using "auto_name" if we didn't find anything else
  if (r["artifact_id"].empty()) {
    r["artifact_id"] = std::move(r["auto_name"]);
    boost::replace_all(r["artifact_id"], ".", "-");
  }

  return r;
}

Row processPomProperties(std::unique_ptr<zip_file_t, ZipFileDeleter>& props,
                  zip_stat_t* stats,
                  const std::string& inner_path,
                  QueryData& results) {
  fs::path p = fs::path(std::string(stats->name));

  std::string buffer;
  buffer.resize(stats->size);
  zip_fread(props.get(), &buffer[0], stats->size);

  Row r;
  populateRow(r, stats->size, p.filename().string(), inner_path + "/" + p.parent_path().string());

  std::istringstream props_in(buffer);
  buffer.clear();

  std::string line;
  while (std::getline(props_in, line)) {
    if (line.empty()) {
      continue;
    }

    auto ch = line.at(0);
    if (ch == ' ' || ch == '#') {
      continue; // Skip comment and continuration lines
    }

    auto kv = osquery::split(line, "=");
    if (kv.size() != 2) {
      continue;
    }

    auto key = kv.at(0);
    if (key == "artifactId") {
      r["artifact_id"] = kv.at(1);
    } else if (key == "groupId") {
      r["group_id"] = kv.at(1);
    } else if (key == "version") {
      r["version"] = kv.at(1);
    }
  }

  return r;
}

Row processSingleSubfile(std::unique_ptr<zip_file_t, ZipFileDeleter>& file,
                         zip_stat_t* stats,
                         const std::string& fname,
                         const std::string& inner_path,
                         QueryData& results) {
  if (fname == "pom.properties") {
    return processPomProperties(file, stats, inner_path, results);
  } else if (fname == "manifest.mf") {
    return processManifestMF(file, stats, inner_path, results);
  }

  fs::path p = fs::path(std::string(stats->name));

  Row r;
  populateRow(r, stats->size, p.filename().string(), inner_path + "/" + stats->name);

  return r;
}

void mergeJarManifestPom(Row& pom, Row& manifest, Row& jar) {
  // prefer metadata extracted from pom.properties
  jar["artifact_id"] = pom["artifact_id"];
  jar["group_id"] = pom["group_id"];
  jar["version"] = pom["version"];

  if (jar["description"].empty()) {
    jar["description"] = manifest["description"];
  }

  if (jar["artifact_id"].empty()) {
    jar["artifact_id"] = manifest["artifact_id"];
  }

  if (jar["group_id"].empty()) {
    jar["group_id"] = manifest["group_id"];
  }

  if (jar["version"].empty()) {
    jar["version"] = manifest["version"];
  }

  if (jar["description"].empty()) {
    jar["description"] = manifest["description"];
  }
}

void mergeJarManifest(Row& manifest, Row& jar) {
  jar["artifact_id"] = manifest["artifact_id"];
  jar["group_id"] = manifest["group_id"];
  jar["version"] = manifest["version"];
  jar["description"] = manifest["description"];
}

void processJar(std::unique_ptr<zip_t, ZipDeleter>& za,
                Row& jar_row,
                const std::string& jar_filename,
                const std::set<std::string>& classes,
                QueryData& results,
                bool nested) {
  std::vector<Row> poms, cls;
  Row manifest_row;
  for (int i = 0; i < zip_get_num_entries(za.get(), 0); i++) {
    zip_stat_t stats;
    if (zip_stat_index(za.get(), i, 0, &stats) == 0) {
      if (stats.name[strlen(stats.name) - 1] == '/') {
        continue;
      }

      fs::path p = fs::path(stats.name);
      std::string fname = p.filename().string();
      std::string fext = p.extension().string();
      boost::to_lower(fname);
      boost::to_lower(fext);

      if (fname != "pom.properties" && fname != "manifest.mf" && fext != ".jar" && classes.empty()) {
        continue;
      }

      std::unique_ptr<zip_file_t, ZipFileDeleter> file = zipFopenIndex(za, i);
      Row r = processSingleSubfile(file, &stats, fname, jar_filename, results);

      if (fname == "pom.properties") {
        poms.push_back(r);
      } else if (fname == "manifest.mf") {
        manifest_row = r;
      } else if (classes.find(r["filename"]) != classes.end()) {
        cls.push_back(r);
      } else if (fext == ".jar") {
        if (!nested) {
          std::string buffer;
          buffer.resize(stats.size);
          zip_fread(file.get(), &buffer[0], stats.size);

          if (true) {
            r["sha256"] = hashFromBuffer(HashType::HASH_TYPE_SHA256, buffer.c_str(), stats.size);
          }

          if (!nested) {
            int err = 0;
            zip_source_t* src = zip_source_buffer_create(&buffer[0], stats.size, 0, (zip_error_t*)&err);

            if (err == ZIP_ER_INVAL || err == ZIP_ER_MEMORY) {
              std::cout  << "Error opening inner JAR file at: " << jar_filename << "/" << stats.name;
              continue;
            }

            std::unique_ptr<zip_t, ZipDeleter> child_zip = zipOpenFromSource(src);
            processJar(child_zip, r, jar_filename + "/" + stats.name, classes, results, true);
          }
        }
      }
    }
  }

  if (poms.size() == 1) {
    // Single pom.properties, MANIFEST.MF exists in the jar.
    // Consolidate by giving preference to pom.properties followed by MANIFEST.MF
    mergeJarManifestPom(poms.front(), manifest_row, jar_row);
  } else {
    // Multiple pom.properties exist. Kind'a uber jar where classes from multiple jars are included
    // Use just MANIFEST.MF details
    mergeJarManifest(manifest_row, jar_row);

    // Add separate entries for each pom.properties found
    for (const auto& r : poms) {
      results.push_back(std::move(r));
    }
  }

  // Add separate entries for each class found
  for (auto& r : cls) {
    mergeJarManifest(manifest_row, r);
    results.push_back(r);
  }

  // If we lack a group_id but the artifact_id has a ., use everything before the last . as the group_id
  if (jar_row["group_id"].empty()) {
    auto lastDot = jar_row["artifact_id"].rfind(".");
    if (lastDot != std::string::npos) {
      jar_row["group_id"] = jar_row["artifact_id"].substr(0, lastDot);
      jar_row["artifact_id"] = jar_row["artifact_id"].substr(lastDot + 1);
    }
  }

  // If the filename matches either the artifact_id or the version number or we couldn't find the artifact_id or version
  // in the metadata, then get the information out of the filename because it seems to be a bit less noisy in practice.
  auto filename = fs::path(jar_filename).stem().string();
  size_t verStart = 0;
  while (verStart != std::string::npos) {
    verStart = filename.find("-", verStart + 1);
    if (verStart < filename.size() - 1 && isdigit(filename[verStart + 1])) {
      break;
    }
  }
  if (verStart != std::string::npos) {
    auto name = filename.substr(0, verStart);
    auto version = filename.substr(verStart + 1);
    if (name == jar_row["artifact_id"] || jar_row["artifact_id"].empty() || version == jar_row["version"] ||
        jar_row["version"].empty()) {
      jar_row["artifact_id"] = name;
      jar_row["version"] = version;
    }
  }
  if (jar_row["artifact_id"].empty()) {
    jar_row["artifact_id"] = filename;
  }

  results.push_back(jar_row);
}

Row genOuterJarResult(const std::string& realPath, const std::string& prettyPath = "") {
  fs::path p = fs::path(prettyPath.empty() ? realPath : prettyPath);

  Row r;
  populateRow(r, fs::file_size(realPath), p.filename().string(), p.string());

  if (true) {
    std::unique_ptr<FILE, decltype(&std::fclose)> f(platformFopen(realPath, "r").get_value_or(0), std::fclose);
    if (!f) {
      std::cout  << "Error opening JAR file for hashing: " << realPath;
      return r;
    }

    Hash jarhash(HASH_TYPE_SHA256);
    std::string jarbuf;
    jarbuf.resize(STREAM_BYTES);
    std::size_t b;
    while ((b = std::fread(&jarbuf[0], sizeof(char), STREAM_BYTES, f.get())) > 0) {
      jarhash.update(&jarbuf[0], b);
    }
    r["sha256"] = jarhash.digest();
  }

  return r;
}

void genJarResults(const std::string& file, const std::set<std::string>& classes, QueryData& results, bool isDirectory) {
  std::vector<std::string> jars;
  if (isDirectory) {
    resolveFilePattern(fs::path(file).append("**"), jars);
  } else {
    jars.push_back(file);
  }

  for (const std::string& path : jars) {
    if (boost::iends_with(path, ".jar") || boost::iends_with(path, ".ear") || boost::iends_with(path, ".war")) {
      Row r = genOuterJarResult(path);
      std::unique_ptr<zip_t, ZipDeleter> za = zipOpen(path);
      processJar(za, r, path, classes, results, false);
    }
  }

  // Specify the input that might be provided in WHERE clause
  for (auto& r : results) {
    if (isDirectory) {
      r["directory"] = file;
    } else {
      r["directory"] = fs::path(file).parent_path().string();
      r["file"] = file;
    }
  }
}

namespace {
std::string setToList(const std::set<std::string>& s) {
  std::string out;
  for (auto& i : s) {
    if (out.empty()) {
      out = i;
    } else {
      out += ", ";
      out += i;
    }
  }
  return out;
}
} // namespace

QueryData genJavaPackages(QueryContext& context) {
  QueryData results;

  std::set<std::string> paths, classes;
  std::map<std::string, std::set<std::string>> directories; // map from directory to exe path
  if (context.constraints.count("directory") > 0 && context.constraints.at("directory").exists(EQUALS)) {
    for (auto& i : context.constraints["directory"].getAll(EQUALS)) {
      directories[i] = std::set<std::string>();
    }
  } else if (context.constraints.count("file") > 0 && context.constraints.at("file").exists(EQUALS)) {
    paths = context.constraints["file"].getAll(EQUALS);
  } 
  if (context.constraints.count("filename") > 0 && context.constraints.at("filename").exists(EQUALS)) {
    classes = context.constraints["filename"].getAll(EQUALS);


  }

  if (!directories.empty()) {
    for (const auto& directory : directories) {
      genJarResults(directory.first, classes, results, true);
    }
  } else if (!paths.empty()) {
    for (const auto& path : paths) {
      genJarResults(path, classes, results, false);
    }
  }
  return results;
}

} // namespace tables
} // namespace osquery


