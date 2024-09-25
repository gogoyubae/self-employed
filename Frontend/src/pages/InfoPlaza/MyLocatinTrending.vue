<template>
  <div>
    <InfoPlazaHeader />
    <div class="container">
      <div class="row align-items-center">
        <!-- 헤딩 -->
        <div class="col-md-6">
          <h1
            class="h3 position-relative pb-sm-2 pb-md-3 mb-5"
            style="z-index: 1021"
          >
            Best 인기 업종 - My 위치
          </h1>
        </div>

        <!-- 필터링 -->
        <div class="row mb-14">
          <!-- 상위 서비스 업종 -->
          <div class="col-md-2">
            <select
              class="form-select round-corner"
              aria-label="Default select example"
            >
              <option selected disabled hidden>상위 서비스 업종</option>
              <option value="1">One</option>
              <option value="2">Two</option>
              <option value="3">Three</option>
            </select>
          </div>

          <!-- 하위 서비스 업종 -->
          <div class="col-md-2">
            <select
              class="form-select round-corner"
              aria-label="Default select example"
            >
              <option selected disabled hidden>하위 서비스 업종</option>
              <option value="1">One</option>
              <option value="2">Two</option>
              <option value="3">Three</option>
            </select>
          </div>

          <div class="col-md-2"></div>
          <div class="col-md-2"></div>

          <!-- 검색창 -->
          <div class="col-md-4">
            <div class="position-relative w-100 d-flex justify-content-md-end">
              <input
                type="search"
                class="form-control form-control-lg"
                placeholder="Search for products"
                aria-label="Search"
                style="
                  border: none;
                  border-bottom: 2px solid #ced4da;
                  border-radius: 0;
                "
              />
              <button
                type="button"
                class="btn btn-icon btn-ghost fs-lg text-bo border-0 position-absolute top-0 end-0 rounded-circle mt-1 me-1"
                aria-label="Search button"
              >
                <i class="fa-solid fa-magnifying-glass"></i>
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- 사업 아이템 리스트 -->
      <div class="row">
        <!-- 사업 아이템 리스트 본문 -->
        <div class="table-responsive">
          <table class="table table-hover table-sm table-nowrap">
            <thead>
              <tr>
                <th scope="col">
                  <div class="d-flex align-items-center gap-2 ps-1">
                    <div class="text-base">
                      <div class="form-check">
                        <input class="form-check-input" type="checkbox" />
                      </div>
                    </div>
                    <span>Handler</span>
                  </div>
                </th>
                <th scope="col">Currency</th>
                <th scope="col">Rate</th>
                <th scope="col">Amount</th>
                <th scope="col" class="d-none d-xl-table-cell">Date</th>
                <th scope="col" class="d-none d-xl-table-cell">Status</th>
                <th scope="col" class="d-none d-xl-table-cell">
                  Required Action
                </th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>
                  <div class="d-flex align-items-center gap-3 ps-1">
                    <div class="text-base">
                      <div class="form-check">
                        <input class="form-check-input" type="checkbox" />
                      </div>
                    </div>
                    <div
                      class="d-none d-xl-inline-flex icon icon-shape w-rem-8 h-rem-8 rounded-circle text-sm bg-secondary bg-opacity-25 text-secondary"
                    >
                      <i class="bi bi-file-fill"></i>
                    </div>
                    <div>
                      <span class="d-block text-heading fw-bold"
                        >Bought BTC</span
                      >
                    </div>
                  </div>
                </td>
                <td class="text-xs">
                  BTC <i class="bi bi-arrow-right mx-2"></i> USDT
                </td>
                <td>1.23</td>
                <td>$1,300,000.00</td>
                <td class="d-none d-xl-table-cell">3 min ago</td>
                <td class="d-none d-xl-table-cell">
                  <span class="badge badge-lg badge-dot">
                    <i class="bg-success"></i>Active
                  </span>
                </td>
                <td class="d-none d-xl-table-cell">Needs your attention</td>
                <td class="text-end">
                  <button
                    type="button"
                    class="btn btn-sm btn-square btn-neutral w-rem-6 h-rem-6"
                  >
                    <i class="bi bi-three-dots"></i>
                  </button>
                </td>
              </tr>
              <tr>
                <td>
                  <div class="d-flex align-items-center gap-3 ps-1">
                    <div class="text-base">
                      <div class="form-check">
                        <input class="form-check-input" type="checkbox" />
                      </div>
                    </div>
                    <div
                      class="d-none d-xl-inline-flex icon icon-shape w-rem-8 h-rem-8 rounded-circle text-sm bg-secondary bg-opacity-25 text-secondary"
                    >
                      <i class="bi bi-file-fill"></i>
                    </div>
                    <div>
                      <span class="d-block text-heading fw-bold">Sold ADA</span>
                    </div>
                  </div>
                </td>
                <td class="text-xs">
                  ADA <i class="bi bi-arrow-right mx-2"></i> USDT
                </td>
                <td>1.23</td>
                <td>$1,300,000.00</td>
                <td class="d-none d-xl-table-cell">3 min ago</td>
                <td class="d-none d-xl-table-cell">
                  <span class="badge badge-lg badge-dot">
                    <i class="bg-success"></i>Active
                  </span>
                </td>
                <td class="d-none d-xl-table-cell">Needs your attention</td>
                <td class="text-end">
                  <button
                    type="button"
                    class="btn btn-sm btn-square btn-neutral w-rem-6 h-rem-6"
                  >
                    <i class="bi bi-three-dots"></i>
                  </button>
                </td>
              </tr>
              <tr>
                <td>
                  <div class="d-flex align-items-center gap-3 ps-1">
                    <div class="text-base">
                      <div class="form-check">
                        <input class="form-check-input" type="checkbox" />
                      </div>
                    </div>
                    <div
                      class="d-none d-xl-inline-flex icon icon-shape w-rem-8 h-rem-8 rounded-circle text-sm bg-secondary bg-opacity-25 text-secondary"
                    >
                      <i class="bi bi-file-fill"></i>
                    </div>
                    <div>
                      <span class="d-block text-heading fw-bold"
                        >Bought XRP</span
                      >
                    </div>
                  </div>
                </td>
                <td class="text-xs">
                  XRP <i class="bi bi-arrow-right mx-2"></i> USDT
                </td>
                <td>1.23</td>
                <td>$1,300,000.00</td>
                <td class="d-none d-xl-table-cell">3 min ago</td>
                <td class="d-none d-xl-table-cell">
                  <span class="badge badge-lg badge-dot">
                    <i class="bg-success"></i>Active
                  </span>
                </td>
                <td class="d-none d-xl-table-cell">Needs your attention</td>
                <td class="text-end">
                  <button
                    type="button"
                    class="btn btn-sm btn-square btn-neutral w-rem-6 h-rem-6"
                  >
                    <i class="bi bi-three-dots"></i>
                  </button>
                </td>
              </tr>
              <tr>
                <td>
                  <div class="d-flex align-items-center gap-3 ps-1">
                    <div class="text-base">
                      <div class="form-check">
                        <input class="form-check-input" type="checkbox" />
                      </div>
                    </div>
                    <div
                      class="d-none d-xl-inline-flex icon icon-shape w-rem-8 h-rem-8 rounded-circle text-sm bg-secondary bg-opacity-25 text-secondary"
                    >
                      <i class="bi bi-file-fill"></i>
                    </div>
                    <div>
                      <span class="d-block text-heading fw-bold"
                        >Robert Fox</span
                      >
                    </div>
                  </div>
                </td>
                <td class="text-xs">
                  BTC <i class="bi bi-arrow-right mx-2"></i> USDT
                </td>
                <td>1.23</td>
                <td>$1,300,000.00</td>
                <td class="d-none d-xl-table-cell">3 min ago</td>
                <td class="d-none d-xl-table-cell">
                  <span class="badge badge-lg badge-dot">
                    <i class="bg-success"></i>Active
                  </span>
                </td>
                <td class="d-none d-xl-table-cell">Needs your attention</td>
                <td class="text-end">
                  <button
                    type="button"
                    class="btn btn-sm btn-square btn-neutral w-rem-6 h-rem-6"
                  >
                    <i class="bi bi-three-dots"></i>
                  </button>
                </td>
              </tr>
              <tr>
                <td>
                  <div class="d-flex align-items-center gap-3 ps-1">
                    <div class="text-base">
                      <div class="form-check">
                        <input class="form-check-input" type="checkbox" />
                      </div>
                    </div>
                    <div
                      class="d-none d-xl-inline-flex icon icon-shape w-rem-8 h-rem-8 rounded-circle text-sm bg-secondary bg-opacity-25 text-secondary"
                    >
                      <i class="bi bi-file-fill"></i>
                    </div>
                    <div>
                      <span class="d-block text-heading fw-bold"
                        >Robert Fox</span
                      >
                    </div>
                  </div>
                </td>
                <td class="text-xs">
                  BTC <i class="bi bi-arrow-right mx-2"></i> USDT
                </td>
                <td>1.23</td>
                <td>$1,300,000.00</td>
                <td class="d-none d-xl-table-cell">3 min ago</td>
                <td class="d-none d-xl-table-cell">
                  <span class="badge badge-lg badge-dot">
                    <i class="bg-success"></i>Active
                  </span>
                </td>
                <td class="d-none d-xl-table-cell">Needs your attention</td>
                <td class="text-end">
                  <button
                    type="button"
                    class="btn btn-sm btn-square btn-neutral w-rem-6 h-rem-6"
                  >
                    <i class="bi bi-three-dots"></i>
                  </button>
                </td>
              </tr>
              <tr>
                <td>
                  <div class="d-flex align-items-center gap-3 ps-1">
                    <div class="text-base">
                      <div class="form-check">
                        <input class="form-check-input" type="checkbox" />
                      </div>
                    </div>
                    <div
                      class="d-none d-xl-inline-flex icon icon-shape w-rem-8 h-rem-8 rounded-circle text-sm bg-secondary bg-opacity-25 text-secondary"
                    >
                      <i class="bi bi-file-fill"></i>
                    </div>
                    <div>
                      <span class="d-block text-heading fw-bold"
                        >Robert Fox</span
                      >
                    </div>
                  </div>
                </td>
                <td class="text-xs">
                  BTC <i class="bi bi-arrow-right mx-2"></i> USDT
                </td>
                <td>1.23</td>
                <td>$1,300,000.00</td>
                <td class="d-none d-xl-table-cell">3 min ago</td>
                <td class="d-none d-xl-table-cell">
                  <span class="badge badge-lg badge-dot">
                    <i class="bg-success"></i>Active
                  </span>
                </td>
                <td class="d-none d-xl-table-cell">Needs your attention</td>
                <td class="text-end">
                  <button
                    type="button"
                    class="btn btn-sm btn-square btn-neutral w-rem-6 h-rem-6"
                  >
                    <i class="bi bi-three-dots"></i>
                  </button>
                </td>
              </tr>
              <tr>
                <td>
                  <div class="d-flex align-items-center gap-3 ps-1">
                    <div class="text-base">
                      <div class="form-check">
                        <input class="form-check-input" type="checkbox" />
                      </div>
                    </div>
                    <div
                      class="d-none d-xl-inline-flex icon icon-shape w-rem-8 h-rem-8 rounded-circle text-sm bg-secondary bg-opacity-25 text-secondary"
                    >
                      <i class="bi bi-file-fill"></i>
                    </div>
                    <div>
                      <span class="d-block text-heading fw-bold"
                        >Robert Fox</span
                      >
                    </div>
                  </div>
                </td>
                <td class="text-xs">
                  BTC <i class="bi bi-arrow-right mx-2"></i> USDT
                </td>
                <td>1.23</td>
                <td>$1,300,000.00</td>
                <td class="d-none d-xl-table-cell">3 min ago</td>
                <td class="d-none d-xl-table-cell">
                  <span class="badge badge-lg badge-dot">
                    <i class="bg-success"></i>Active
                  </span>
                </td>
                <td class="d-none d-xl-table-cell">Needs your attention</td>
                <td class="text-end">
                  <button
                    type="button"
                    class="btn btn-sm btn-square btn-neutral w-rem-6 h-rem-6"
                  >
                    <i class="bi bi-three-dots"></i>
                  </button>
                </td>
              </tr>
              <tr>
                <td>
                  <div class="d-flex align-items-center gap-3 ps-1">
                    <div class="text-base">
                      <div class="form-check">
                        <input class="form-check-input" type="checkbox" />
                      </div>
                    </div>
                    <div
                      class="d-none d-xl-inline-flex icon icon-shape w-rem-8 h-rem-8 rounded-circle text-sm bg-secondary bg-opacity-25 text-secondary"
                    >
                      <i class="bi bi-file-fill"></i>
                    </div>
                    <div>
                      <span class="d-block text-heading fw-bold"
                        >Robert Fox</span
                      >
                    </div>
                  </div>
                </td>
                <td class="text-xs">
                  BTC <i class="bi bi-arrow-right mx-2"></i> USDT
                </td>
                <td>1.23</td>
                <td>$1,300,000.00</td>
                <td class="d-none d-xl-table-cell">3 min ago</td>
                <td class="d-none d-xl-table-cell">
                  <span class="badge badge-lg badge-dot">
                    <i class="bg-success"></i>Active
                  </span>
                </td>
                <td class="d-none d-xl-table-cell">Needs your attention</td>
                <td class="text-end">
                  <button
                    type="button"
                    class="btn btn-sm btn-square btn-neutral w-rem-6 h-rem-6"
                  >
                    <i class="bi bi-three-dots"></i>
                  </button>
                </td>
              </tr>
              <tr>
                <td>
                  <div class="d-flex align-items-center gap-3 ps-1">
                    <div class="text-base">
                      <div class="form-check">
                        <input class="form-check-input" type="checkbox" />
                      </div>
                    </div>
                    <div
                      class="d-none d-xl-inline-flex icon icon-shape w-rem-8 h-rem-8 rounded-circle text-sm bg-secondary bg-opacity-25 text-secondary"
                    >
                      <i class="bi bi-file-fill"></i>
                    </div>
                    <div>
                      <span class="d-block text-heading fw-bold"
                        >Robert Fox</span
                      >
                    </div>
                  </div>
                </td>
                <td class="text-xs">
                  BTC <i class="bi bi-arrow-right mx-2"></i> USDT
                </td>
                <td>1.23</td>
                <td>$1,300,000.00</td>
                <td class="d-none d-xl-table-cell">3 min ago</td>
                <td class="d-none d-xl-table-cell">
                  <span class="badge badge-lg badge-dot">
                    <i class="bg-success"></i>Active
                  </span>
                </td>
                <td class="d-none d-xl-table-cell">Needs your attention</td>
                <td class="text-end">
                  <button
                    type="button"
                    class="btn btn-sm btn-square btn-neutral w-rem-6 h-rem-6"
                  >
                    <i class="bi bi-three-dots"></i>
                  </button>
                </td>
              </tr>
              <tr>
                <td>
                  <div class="d-flex align-items-center gap-3 ps-1">
                    <div class="text-base">
                      <div class="form-check">
                        <input class="form-check-input" type="checkbox" />
                      </div>
                    </div>
                    <div
                      class="d-none d-xl-inline-flex icon icon-shape w-rem-8 h-rem-8 rounded-circle text-sm bg-secondary bg-opacity-25 text-secondary"
                    >
                      <i class="bi bi-file-fill"></i>
                    </div>
                    <div>
                      <span class="d-block text-heading fw-bold"
                        >Robert Fox</span
                      >
                    </div>
                  </div>
                </td>
                <td class="text-xs">
                  BTC <i class="bi bi-arrow-right mx-2"></i> USDT
                </td>
                <td>1.23</td>
                <td>$1,300,000.00</td>
                <td class="d-none d-xl-table-cell">3 min ago</td>
                <td class="d-none d-xl-table-cell">
                  <span class="badge badge-lg badge-dot">
                    <i class="bg-success"></i>Active
                  </span>
                </td>
                <td class="d-none d-xl-table-cell">Needs your attention</td>
                <td class="text-end">
                  <button
                    type="button"
                    class="btn btn-sm btn-square btn-neutral w-rem-6 h-rem-6"
                  >
                    <i class="bi bi-three-dots"></i>
                  </button>
                </td>
              </tr>
              <tr>
                <td>
                  <div class="d-flex align-items-center gap-3 ps-1">
                    <div class="text-base">
                      <div class="form-check">
                        <input class="form-check-input" type="checkbox" />
                      </div>
                    </div>
                    <div
                      class="d-none d-xl-inline-flex icon icon-shape w-rem-8 h-rem-8 rounded-circle text-sm bg-secondary bg-opacity-25 text-secondary"
                    >
                      <i class="bi bi-file-fill"></i>
                    </div>
                    <div>
                      <span class="d-block text-heading fw-bold"
                        >Robert Fox</span
                      >
                    </div>
                  </div>
                </td>
                <td class="text-xs">
                  BTC <i class="bi bi-arrow-right mx-2"></i> USDT
                </td>
                <td>1.23</td>
                <td>$1,300,000.00</td>
                <td class="d-none d-xl-table-cell">3 min ago</td>
                <td class="d-none d-xl-table-cell">
                  <span class="badge badge-lg badge-dot">
                    <i class="bg-success"></i>Active
                  </span>
                </td>
                <td class="d-none d-xl-table-cell">Needs your attention</td>
                <td class="text-end">
                  <button
                    type="button"
                    class="btn btn-sm btn-square btn-neutral w-rem-6 h-rem-6"
                  >
                    <i class="bi bi-three-dots"></i>
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <!-- 페이지네이션 -->
        <div class="py-4 px-6">
          <div class="row align-items-center justify-content-between">
            <div class="col-md-6 d-none d-md-block">
              <span class="text-muted text-sm"
                >Showing 10 items out of 250 results found</span
              >
            </div>
            <div class="col-md-auto">
              <nav aria-label="Page navigation example">
                <ul class="pagination pagination-spaced gap-1">
                  <li class="page-item">
                    <a class="page-link" href="#">
                      <i class="bi bi-chevron-left"></i>
                    </a>
                  </li>
                  <li class="page-item"><a class="page-link" href="#">1</a></li>
                  <li class="page-item"><a class="page-link" href="#">2</a></li>
                  <li class="page-item"><a class="page-link" href="#">3</a></li>
                  <li class="page-item"><a class="page-link" href="#">4</a></li>
                  <li class="page-item"><a class="page-link" href="#">5</a></li>
                  <li class="page-item">
                    <a class="page-link" href="#">
                      <i class="bi bi-chevron-right"></i>
                    </a>
                  </li>
                </ul>
              </nav>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import InfoPlazaHeader from '@/components/infoplaza/InfoPlazaHeader.vue';
</script>

<style scoped>
.round-corner {
  border-radius: 20px;
}
</style>
