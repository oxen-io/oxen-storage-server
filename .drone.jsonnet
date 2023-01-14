local default_deps_base = [
  'autoconf',
  'libboost-program-options-dev',
  'libcurl4-openssl-dev',
  'libjemalloc-dev',
  'libsodium-dev',
  'libsqlite3-dev',
  'libssl-dev',
  'libsystemd-dev',
  'make',
  'pkg-config',
];
local default_deps_nocxx = ['libsodium-dev'] + default_deps_base;  // libsodium-dev needs to be >= 1.0.18
local default_deps = ['g++'] + default_deps_nocxx;  // g++ sometimes needs replacement
local docker_base = 'registry.oxen.rocks/lokinet-ci-';

local submodules_commands = ['git fetch --tags', 'git submodule update --init --recursive --depth=1 --jobs=4'];
local submodules = {
  name: 'submodules',
  image: 'drone/git',
  commands: submodules_commands,
};

local apt_get_quiet = 'apt-get -o=Dpkg::Use-Pty=0 -q';

local cmake_options(opts) = std.join(' ', [' -D' + o + '=' + (if opts[o] then 'ON' else 'OFF') for o in std.objectFields(opts)]) + ' ';

// Regular build on a debian-like system:
local debian_pipeline(name,
                      image,
                      arch='amd64',
                      deps=default_deps,
                      build_type='Release',
                      lto=false,
                      werror=true,
                      build_tests=true,
                      run_tests=true,  // Runs full test suite
                      test_oxen_storage=true,  // Makes sure oxen-storage --version runs
                      cmake_extra='',
                      extra_cmds=[],
                      extra_steps=[],
                      jobs=6,
                      oxen_repo=false,
                      allow_fail=false) = {
  kind: 'pipeline',
  type: 'docker',
  name: name,
  platform: { arch: arch },
  steps: [
    submodules,
    {
      name: 'build',
      image: image,
      pull: 'always',
      [if allow_fail then 'failure']: 'ignore',
      environment: { SSH_KEY: { from_secret: 'SSH_KEY' } },
      commands: [
                  'echo "Building on ${DRONE_STAGE_MACHINE}"',
                  'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
                  apt_get_quiet + ' update',
                  apt_get_quiet + ' install -y eatmydata',
                ] + (
                  if oxen_repo then [
                    'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y lsb-release',
                    'cp contrib/deb.oxen.io.gpg /etc/apt/trusted.gpg.d',
                    'echo deb http://deb.oxen.io $$(lsb_release -sc) main >/etc/apt/sources.list.d/oxen.list',
                    'eatmydata ' + apt_get_quiet + ' update',
                  ] else []
                ) + [
                  'eatmydata ' + apt_get_quiet + ' dist-upgrade -y',
                  'eatmydata ' + apt_get_quiet + ' install -y --no-install-recommends cmake git ca-certificates ninja-build ccache '
                  + std.join(' ', deps),
                  'mkdir build',
                  'cd build',
                  'cmake .. -G Ninja -DCMAKE_CXX_FLAGS=-fdiagnostics-color=always -DCMAKE_BUILD_TYPE=' + build_type
                  + ' -DLOCAL_MIRROR=https://oxen.rocks/deps -DEXTRA_WARNINGS=ON '
                  + cmake_options({ USE_LTO: lto, WARNINGS_AS_ERRORS: werror, BUILD_TESTS: build_tests || run_tests })
                  + cmake_extra,
                  'ninja -j' + jobs + ' -v',
                ] +
                (if test_oxen_storage then ['./oxen-storage --version'] else []) +
                (if run_tests then ['./unit_test/Test'] else []) +
                extra_cmds,
    },
  ] + extra_steps,
};

local clang(version, lto=false) = debian_pipeline(
  'Debian sid/clang-' + version + ' (amd64)',
  docker_base + 'debian-sid-clang',
  deps=['clang-' + version] + default_deps_nocxx,
  cmake_extra='-DCMAKE_C_COMPILER=clang-' + version + ' -DCMAKE_CXX_COMPILER=clang++-' + version + ' ',
  lto=lto
);

// Macos build
local mac_builder(name,
                  build_type='Release',
                  lto=false,
                  werror=true,
                  build_tests=true,
                  run_tests=true,
                  test_oxen_storage=true,  // Makes sure oxen-storage --version runs
                  cmake_extra='',
                  extra_cmds=[],
                  extra_steps=[],
                  jobs=6,
                  allow_fail=false) = {
  kind: 'pipeline',
  type: 'exec',
  name: name,
  platform: { os: 'darwin', arch: 'amd64' },
  steps: [
    { name: 'submodules', commands: submodules_commands },
    {
      name: 'build',
      environment: { SSH_KEY: { from_secret: 'SSH_KEY' } },
      commands: [
                  // If you don't do this then the C compiler doesn't have an include path containing
                  // basic system headers.  WTF apple:
                  'export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"',
                  'mkdir build',
                  'cd build',
                  'cmake .. -G Ninja -DCMAKE_CXX_FLAGS=-fcolor-diagnostics -DCMAKE_BUILD_TYPE=' + build_type
                  + ' -DLOCAL_MIRROR=https://oxen.rocks/deps -DEXTRA_WARNINGS=ON '
                  + cmake_options({ USE_LTO: lto, WARNINGS_AS_ERRORS: werror, BUILD_TESTS: build_tests || run_tests })
                  + cmake_extra,
                  'ninja -j' + jobs + ' -v',
                ] +
                (if test_oxen_storage then ['./oxen-storage --version'] else []) +
                (if run_tests then ['./unit_test/Test'] else []) +
                extra_cmds,
    },
  ] + extra_steps,
};

local static_check_and_upload = [
  '../contrib/drone-check-static-libs.sh',
  'ninja strip',
  'ninja create_tarxz',
  '../contrib/drone-static-upload.sh',
];


[
  {
    name: 'lint check',
    kind: 'pipeline',
    type: 'docker',
    steps: [{
      name: 'build',
      image: docker_base + 'lint',
      pull: 'always',
      commands: [
        'echo "Building on ${DRONE_STAGE_MACHINE}"',
        apt_get_quiet + ' update',
        apt_get_quiet + ' install -y eatmydata',
        'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y git clang-format-14 jsonnet',
        './contrib/drone-format-verify.sh',
      ],
    }],
  },

  // Various debian builds
  debian_pipeline('Debian (amd64)', docker_base + 'debian-sid', lto=true),
  debian_pipeline('Debian Debug (amd64)', docker_base + 'debian-sid', build_type='Debug'),
  clang(14, lto=true),
  debian_pipeline('Debian stable (i386)', docker_base + 'debian-stable/i386'),
  debian_pipeline('Ubuntu LTS (amd64)', docker_base + 'ubuntu-lts'),
  debian_pipeline('Ubuntu latest (amd64)', docker_base + 'ubuntu-rolling'),
  debian_pipeline('Debian buster (amd64)',
                  docker_base + 'debian-buster',
                  deps=default_deps_base + ['g++', 'file'],
                  cmake_extra='-DDOWNLOAD_SODIUM=ON'),

  // ARM builds (ARM64 and armhf)
  debian_pipeline('Debian sid (ARM64)', docker_base + 'debian-sid', arch='arm64'),
  debian_pipeline('Debian stable (armhf)', docker_base + 'debian-stable/arm32v7', arch='arm64'),

  // Static build (on bionic) which gets uploaded to oxen.rocks:
  debian_pipeline('Static (bionic amd64)',
                  docker_base + 'ubuntu-bionic',
                  deps=['autoconf', 'automake', 'file', 'g++-8', 'libtool', 'make', 'openssh-client', 'patch', 'pkg-config'],
                  cmake_extra='-DBUILD_STATIC_DEPS=ON -DCMAKE_C_COMPILER=gcc-8 -DCMAKE_CXX_COMPILER=g++-8',
                  lto=true,
                  oxen_repo=true,  // for updated cmake
                  extra_cmds=static_check_and_upload),

  // Macos builds:
  mac_builder('macOS (Static)',
              cmake_extra='-DBUILD_STATIC_DEPS=ON',
              lto=true,
              extra_cmds=static_check_and_upload),
  mac_builder('macOS (Release)'),
  mac_builder('macOS (Debug)', build_type='Debug'),
]
