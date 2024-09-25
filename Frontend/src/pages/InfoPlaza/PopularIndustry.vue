<template>
  <div>
    <InfoPlazaHeader />
    <div class="container mw-screen-xl">
      <!-- Title  -->
      <div class="row">
        <h2 style="font-weight: 700">
          <i class="fa-solid fa-fire"></i> BEST 인기 업종
        </h2>
      </div>
      <br />

      <div class="row">
        <!-- 성별 연령대 1등 카드 -->
        <div class="col-xl-3 col-md-6 mb-4">
          <div class="card border-left-primary shadow h-100 py-2">
            <div
              class="card-body d-flex flex-column justify-content-center align-items-center"
            >
              <div
                class="row no-gutters align-items-center justify-content-center"
              >
                <div class="col text-center">
                  <div class="h4 mb-3 text-gray-300">강남구 압구정동</div>
                  <div class="h4 mb-4 text-gray-300">압구정로데오사거리</div>
                  <div
                    class="h3 mb-5 font-weight-bold text-success text-gray-800"
                  >
                    음식 음료
                  </div>
                </div>
              </div>
              <!-- 아이콘을 새로운 div로 감싸서 중앙 정렬 -->
              <div class="text-center mt-3">
                <i class="fa-solid fa-trophy" style="font-size: 100px"></i>
              </div>
            </div>
          </div>
        </div>

        <!-- 성별 연령대 2등 카드 -->
        <div class="col-xl-2 col-md-6 mb-4">
          <div class="card border-left-primary shadow h-70 py-2 mt-16">
            <div
              class="card-body d-flex flex-column justify-content-center align-items-center"
            >
              <div
                class="row no-gutters align-items-center justify-content-center"
              >
                <div class="col text-center">
                  <div class="h6 mb-3 text-gray-300">강남구 압구정동</div>
                  <div class="h6 mb-4 text-gray-300">압구정로데오사거리</div>
                  <div
                    class="h5 mb-5 font-weight-bold text-success text-gray-800"
                  >
                    음식 음료
                  </div>
                </div>
              </div>
              <!-- 아이콘을 새로운 div로 감싸서 중앙 정렬 -->
              <div class="text-center mt-3">
                <i class="fa-solid fa-trophy" style="font-size: 50px"></i>
              </div>
            </div>
          </div>
        </div>

        <!-- 성별 연령대 3등 카드 -->
        <div class="col-xl-2 col-md-6 mb-4 me">
          <div class="card border-left-primary shadow h-70 py-2 mt-16">
            <div
              class="card-body d-flex flex-column justify-content-center align-items-center"
            >
              <div
                class="row no-gutters align-items-center justify-content-center"
              >
                <div class="col text-center">
                  <div class="h6 mb-3 text-gray-300">강남구 압구정동</div>
                  <div class="h6 mb-4 text-gray-300">압구정로데오사거리</div>
                  <div
                    class="h5 mb-5 font-weight-bold text-success text-gray-800"
                  >
                    음식 음료
                  </div>
                </div>
              </div>
              <!-- 아이콘을 새로운 div로 감싸서 중앙 정렬 -->
              <div class="text-center mt-3">
                <i class="fa-solid fa-trophy" style="font-size: 50px"></i>
              </div>
            </div>
          </div>
        </div>

        <div class="col-xl-1 col-md-6 mb-4"></div>
        <!-- 필터링 -->
        <div class="col-xl-4 col-md-6 mb-4">
          <!-- 성별 -->
          <label for="inputEmail3" class="fw-bold" style="font-size: 1rem">
            성별</label
          >

          <div class="mt-2">
            <div class="form-check form-check-inline">
              <input
                type="checkbox"
                class="form-check-input"
                id="cycleCheck1"
              />
              <label class="form-check-label" for="cycleCheck1">전체</label>
            </div>
            <div class="form-check form-check-inline">
              <input
                type="checkbox"
                class="form-check-input"
                id="cycleCheck2"
              />
              <label class="form-check-label" for="cycleCheck2">남성</label>
            </div>
            <div class="form-check form-check-inline">
              <input
                type="checkbox"
                class="form-check-input"
                id="cycleCheck3"
              />
              <label class="form-check-label" for="cycleCheck3">여성</label>
            </div>
          </div>

          <!-- 연령대 checkbox -->
          <label for="inputEmail3" class="fw-bold mt-20" style="font-size: 1rem"
            >연령대</label
          >
          <div class="col-9">
            <div class="mt-2">
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="cycleCheck1"
                />
                <label class="form-check-label" for="cycleCheck1">전체</label>
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="cycleCheck2"
                />
                <label class="form-check-label" for="cycleCheck2">10대</label>
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="cycleCheck3"
                />
                <label class="form-check-label" for="cycleCheck3">20대</label>
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="cycleCheck4"
                />
                <label class="form-check-label" for="cycleCheck4">30대</label>
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="cycleCheck4"
                />
                <label class="form-check-label" for="cycleCheck4">40대</label>
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="cycleCheck4"
                />
                <label class="form-check-label" for="cycleCheck4">50대</label>
              </div>
              <div class="form-check form-check-inline">
                <input
                  type="checkbox"
                  class="form-check-input"
                  id="cycleCheck4"
                />
                <label class="form-check-label" for="cycleCheck4"
                  >60대 이상</label
                >
              </div>
            </div>
          </div>
        </div>
      </div>

      <div
        class="row mt-20"
        style="display: flex; justify-content: center; align-items: center"
      >
        <!-- 전체 지역, 최근 리포트에서 선정한 지역의 핫한 아이템  -->
        <div
          class="row"
          style="display: flex; justify-content: center; align-items: center"
        >
          <!-- 전체 지역에서 핫한 사업 아이템 베스트 -->
          <div class="col-xxl-4 mb-xxl-10">
            <!--begin::List widget 7-->
            <div class="card card-flush h-md-100">
              <!--begin::Header-->
              <div class="card-header py-7">
                <!--begin::Statistics-->
                <div class="m-0">
                  <!--begin::Heading-->
                  <div class="d-flex align-items-center mb-2">
                    <!--begin::Title-->
                    <span class="fs-2hx fw-bold text-gray-800 lh-1 ls-n2">
                      전체 지역에서 핫한 사업 아이템
                    </span>
                    <!--end::Title-->
                    <router-link
                      to="/infoPlaza/industry/TotalTrendingBusinessItems"
                      class="ms-auto"
                      style="font-size: 13px"
                    >
                      <i class="fa-solid fa-arrow-up-right-from-square"></i>
                      더보기
                    </router-link>
                  </div>
                  <!--end::Heading-->
                </div>
                <!--end::Statistics-->
                <!--begin::Toolbar-->
                <div class="card-toolbar"></div>
                <!--end::Toolbar-->
              </div>
              <!--end::Header-->
              <!--begin::Body-->
              <div class="card-body pt-0">
                <!--begin::Items-->
                <div class="mb-0">
                  <!--begin::Item-->
                  <div class="d-flex flex-stack mt-3">
                    <!--begin::Section-->
                    <div
                      class="d-flex align-items-center me-5"
                      style="flex-grow: 1"
                    >
                      <!--begin::Symbol-->
                      <div class="symbol symbol-30px me-5">
                        <span class="symbol-label">
                          <i class="ki-duotone ki-magnifier fs-3 text-gray-600">
                            <!-- 아이콘 사진 넣는 곳 -->
                            <i class="fa-solid fa-bowl-food"></i>
                          </i>
                        </span>
                      </div>
                      <!--end::Symbol-->
                      <!--begin::Content-->
                      <div class="me-auto">
                        <!--begin::Title-->
                        <p style="color: black; font-size: 1rem">한식음식점</p>
                        <!--end::Desc-->
                      </div>
                      <!--end::Content-->
                    </div>
                    <!--end::Section-->
                    <!--begin::Wrapper-->
                    <div class="d-flex align-items-center">
                      <!--begin::Number-->
                      <span class="text-gray-800 fw-bold fs-6 me-3">124%</span>
                      <!--end::Number-->
                      <!--begin::Info-->
                      <div class="d-flex flex-center">
                        <!--begin::label-->
                        <span class="badge badge-light-success fs-base">
                          <i class="fa-solid fa-angle-up"></i> 4 점포
                        </span>
                        <!--end::label-->
                      </div>
                      <!--end::Info-->
                    </div>
                    <!--end::Wrapper-->
                  </div>
                  <!--end::Item-->
                  <!--begin::Separator-->
                  <hr />
                  <!--end::Separator-->
                  <!--begin::Item-->
                  <div class="d-flex flex-stack mt-3">
                    <!--begin::Section-->
                    <div
                      class="d-flex align-items-center me-5"
                      style="flex-grow: 1"
                    >
                      <!--begin::Symbol-->
                      <div class="symbol symbol-30px me-5">
                        <span class="symbol-label">
                          <i class="ki-duotone ki-magnifier fs-3 text-gray-600">
                            <!-- 아이콘 사진 넣는 곳 -->
                            <i class="fa-solid fa-bowl-food"></i>
                          </i>
                        </span>
                      </div>
                      <!--end::Symbol-->
                      <!--begin::Content-->
                      <div class="me-auto">
                        <!--begin::Title-->
                        <p style="color: black; font-size: 1rem">한식음식점</p>
                        <!--end::Desc-->
                      </div>
                      <!--end::Content-->
                    </div>
                    <!--end::Section-->
                    <!--begin::Wrapper-->
                    <div class="d-flex align-items-center">
                      <!--begin::Number-->
                      <span class="text-gray-800 fw-bold fs-6 me-3">124%</span>
                      <!--end::Number-->
                      <!--begin::Info-->
                      <div class="d-flex flex-center">
                        <!--begin::label-->
                        <span class="badge badge-light-success fs-base">
                          <i class="fa-solid fa-angle-up"></i> 4 점포
                        </span>
                        <!--end::label-->
                      </div>
                      <!--end::Info-->
                    </div>
                    <!--end::Wrapper-->
                  </div>
                  <!--end::Item-->
                  <!--begin::Separator-->
                  <hr />
                  <!--end::Separator-->
                  <!--begin::Item-->
                  <div class="d-flex flex-stack mt-3">
                    <!--begin::Section-->
                    <div
                      class="d-flex align-items-center me-5"
                      style="flex-grow: 1"
                    >
                      <!--begin::Symbol-->
                      <div class="symbol symbol-30px me-5">
                        <span class="symbol-label">
                          <i class="ki-duotone ki-magnifier fs-3 text-gray-600">
                            <!-- 아이콘 사진 넣는 곳 -->
                            <i class="fa-solid fa-bowl-food"></i>
                          </i>
                        </span>
                      </div>
                      <!--end::Symbol-->
                      <!--begin::Content-->
                      <div class="me-auto">
                        <!--begin::Title-->
                        <p style="color: black; font-size: 1rem">한식음식점</p>
                        <!--end::Desc-->
                      </div>
                      <!--end::Content-->
                    </div>
                    <!--end::Section-->
                    <!--begin::Wrapper-->
                    <div class="d-flex align-items-center">
                      <!--begin::Number-->
                      <span class="text-gray-800 fw-bold fs-6 me-3">124%</span>
                      <!--end::Number-->
                      <!--begin::Info-->
                      <div class="d-flex flex-center">
                        <!--begin::label-->
                        <span class="badge badge-light-success fs-base">
                          <i class="fa-solid fa-angle-up"></i> 4 점포
                        </span>
                        <!--end::label-->
                      </div>
                      <!--end::Info-->
                    </div>
                    <!--end::Wrapper-->
                  </div>
                  <!--end::Item-->
                  <!--begin::Separator-->
                  <hr />
                  <!--end::Separator-->
                  <!--begin::Item-->
                  <div class="d-flex flex-stack mt-3">
                    <!--begin::Section-->
                    <div
                      class="d-flex align-items-center me-5"
                      style="flex-grow: 1"
                    >
                      <!--begin::Symbol-->
                      <div class="symbol symbol-30px me-5">
                        <span class="symbol-label">
                          <i class="ki-duotone ki-magnifier fs-3 text-gray-600">
                            <!-- 아이콘 사진 넣는 곳 -->
                            <i class="fa-solid fa-bowl-food"></i>
                          </i>
                        </span>
                      </div>
                      <!--end::Symbol-->
                      <!--begin::Content-->
                      <div class="me-auto">
                        <!--begin::Title-->
                        <p style="color: black; font-size: 1rem">한식음식점</p>
                        <!--end::Desc-->
                      </div>
                      <!--end::Content-->
                    </div>
                    <!--end::Section-->
                    <!--begin::Wrapper-->
                    <div class="d-flex align-items-center">
                      <!--begin::Number-->
                      <span class="text-gray-800 fw-bold fs-6 me-3">124%</span>
                      <!--end::Number-->
                      <!--begin::Info-->
                      <div class="d-flex flex-center">
                        <!--begin::label-->
                        <span class="badge badge-light-success fs-base">
                          <i class="fa-solid fa-angle-up"></i> 4 점포
                        </span>
                        <!--end::label-->
                      </div>
                      <!--end::Info-->
                    </div>
                    <!--end::Wrapper-->
                  </div>
                  <!--end::Item-->
                  <!--begin::Separator-->
                  <hr />
                  <!--end::Separator-->
                  <!--begin::Item-->
                  <div class="d-flex flex-stack mt-3">
                    <!--begin::Section-->
                    <div
                      class="d-flex align-items-center me-5"
                      style="flex-grow: 1"
                    >
                      <!--begin::Symbol-->
                      <div class="symbol symbol-30px me-5">
                        <span class="symbol-label">
                          <i class="ki-duotone ki-magnifier fs-3 text-gray-600">
                            <!-- 아이콘 사진 넣는 곳 -->
                            <i class="fa-solid fa-bowl-food"></i>
                          </i>
                        </span>
                      </div>
                      <!--end::Symbol-->
                      <!--begin::Content-->
                      <div class="me-auto">
                        <!--begin::Title-->
                        <p style="color: black; font-size: 1rem">한식음식점</p>
                        <!--end::Desc-->
                      </div>
                      <!--end::Content-->
                    </div>
                    <!--end::Section-->
                    <!--begin::Wrapper-->
                    <div class="d-flex align-items-center">
                      <!--begin::Number-->
                      <span class="text-gray-800 fw-bold fs-6 me-3">124%</span>
                      <!--end::Number-->
                      <!--begin::Info-->
                      <div class="d-flex flex-center">
                        <!--begin::label-->
                        <span class="badge badge-light-success fs-base">
                          <i class="fa-solid fa-angle-up"></i> 4 점포
                        </span>
                        <!--end::label-->
                      </div>
                      <!--end::Info-->
                    </div>
                    <!--end::Wrapper-->
                  </div>
                  <!--end::Item-->
                </div>
                <!--end::Items-->
              </div>
              <!--end::Body-->
            </div>
            <!--end::List widget 7-->
          </div>

          <!-- 최근 리포트에서 선정하신 지역에서 핫한 사업 아이템 베스트 -->
          <div class="col-xxl-4 mb-xxl-10">
            <!--begin::List widget 7-->
            <div class="card card-flush h-md-100">
              <!--begin::Header-->
              <div class="card-header py-7">
                <!--begin::Statistics-->
                <div class="m-0">
                  <!--begin::Heading-->
                  <div class="d-flex align-items-center mb-2">
                    <!--begin::Title-->
                    <span class="fs-2hx fw-bold text-gray-800 lh-1 ls-n2">
                      최근 리포트에서 선정하신 지역에서
                      <span style="margin-bottom: 5px; display: block"></span>
                      <!-- 원하는 여백으로 조정 -->
                      핫한 사업 아이템
                    </span>
                    <router-link
                      to="/infoPlaza/industry/TotalTrendingBusinessItems"
                      class="ms-auto"
                      style="font-size: 13px"
                    >
                      <i class="fa-solid fa-arrow-up-right-from-square"></i>
                      더보기
                    </router-link>
                    <!--end::Title-->
                  </div>
                  <!--end::Heading-->
                </div>
                <!--end::Statistics-->
                <!--begin::Toolbar-->
                <div class="card-toolbar"></div>
                <!--end::Toolbar-->
              </div>
              <!--end::Header-->
              <!--begin::Body-->
              <div class="card-body pt-0">
                <!--begin::Items-->
                <div class="mb-0">
                  <!--begin::Item-->
                  <div class="d-flex flex-stack mt-3">
                    <!--begin::Section-->
                    <div
                      class="d-flex align-items-center me-5"
                      style="flex-grow: 1"
                    >
                      <!--begin::Symbol-->
                      <div class="symbol symbol-30px me-5">
                        <span class="symbol-label">
                          <i class="ki-duotone ki-magnifier fs-3 text-gray-600">
                            <!-- 아이콘 사진 넣는 곳 -->
                            <i class="fa-solid fa-bowl-food"></i>
                          </i>
                        </span>
                      </div>
                      <!--end::Symbol-->
                      <!--begin::Content-->
                      <div class="me-auto">
                        <!--begin::Title-->
                        <p style="color: black; font-size: 1rem">한식음식점</p>
                        <!--end::Desc-->
                      </div>
                      <!--end::Content-->
                    </div>
                    <!--end::Section-->
                    <!--begin::Wrapper-->
                    <div class="d-flex align-items-center">
                      <!--begin::Number-->
                      <span class="text-gray-800 fw-bold fs-6 me-3">124%</span>
                      <!--end::Number-->
                      <!--begin::Info-->
                      <div class="d-flex flex-center">
                        <!--begin::label-->
                        <span class="badge badge-light-success fs-base">
                          <i class="fa-solid fa-angle-up"></i> 4 점포
                        </span>
                        <!--end::label-->
                      </div>
                      <!--end::Info-->
                    </div>
                    <!--end::Wrapper-->
                  </div>
                  <!--end::Item-->
                  <!--begin::Separator-->
                  <hr />
                  <!--end::Separator-->
                  <!--begin::Item-->
                  <div class="d-flex flex-stack mt-3">
                    <!--begin::Section-->
                    <div
                      class="d-flex align-items-center me-5"
                      style="flex-grow: 1"
                    >
                      <!--begin::Symbol-->
                      <div class="symbol symbol-30px me-5">
                        <span class="symbol-label">
                          <i class="ki-duotone ki-magnifier fs-3 text-gray-600">
                            <!-- 아이콘 사진 넣는 곳 -->
                            <i class="fa-solid fa-bowl-food"></i>
                          </i>
                        </span>
                      </div>
                      <!--end::Symbol-->
                      <!--begin::Content-->
                      <div class="me-auto">
                        <!--begin::Title-->
                        <p style="color: black; font-size: 1rem">한식음식점</p>
                        <!--end::Desc-->
                      </div>
                      <!--end::Content-->
                    </div>
                    <!--end::Section-->
                    <!--begin::Wrapper-->
                    <div class="d-flex align-items-center">
                      <!--begin::Number-->
                      <span class="text-gray-800 fw-bold fs-6 me-3">124%</span>
                      <!--end::Number-->
                      <!--begin::Info-->
                      <div class="d-flex flex-center">
                        <!--begin::label-->
                        <span class="badge badge-light-success fs-base">
                          <i class="fa-solid fa-angle-up"></i> 4 점포
                        </span>
                        <!--end::label-->
                      </div>
                      <!--end::Info-->
                    </div>
                    <!--end::Wrapper-->
                  </div>
                  <!--end::Item-->
                  <!--begin::Separator-->
                  <hr />
                  <!--end::Separator-->
                  <!--begin::Item-->
                  <div class="d-flex flex-stack mt-3">
                    <!--begin::Section-->
                    <div
                      class="d-flex align-items-center me-5"
                      style="flex-grow: 1"
                    >
                      <!--begin::Symbol-->
                      <div class="symbol symbol-30px me-5">
                        <span class="symbol-label">
                          <i class="ki-duotone ki-magnifier fs-3 text-gray-600">
                            <!-- 아이콘 사진 넣는 곳 -->
                            <i class="fa-solid fa-bowl-food"></i>
                          </i>
                        </span>
                      </div>
                      <!--end::Symbol-->
                      <!--begin::Content-->
                      <div class="me-auto">
                        <!--begin::Title-->
                        <p style="color: black; font-size: 1rem">한식음식점</p>
                        <!--end::Desc-->
                      </div>
                      <!--end::Content-->
                    </div>
                    <!--end::Section-->
                    <!--begin::Wrapper-->
                    <div class="d-flex align-items-center">
                      <!--begin::Number-->
                      <span class="text-gray-800 fw-bold fs-6 me-3">124%</span>
                      <!--end::Number-->
                      <!--begin::Info-->
                      <div class="d-flex flex-center">
                        <!--begin::label-->
                        <span class="badge badge-light-success fs-base">
                          <i class="fa-solid fa-angle-up"></i> 4 점포
                        </span>
                        <!--end::label-->
                      </div>
                      <!--end::Info-->
                    </div>
                    <!--end::Wrapper-->
                  </div>
                  <!--end::Item-->
                  <!--begin::Separator-->
                  <hr />
                  <!--end::Separator-->
                  <!--begin::Item-->
                  <div class="d-flex flex-stack mt-3">
                    <!--begin::Section-->
                    <div
                      class="d-flex align-items-center me-5"
                      style="flex-grow: 1"
                    >
                      <!--begin::Symbol-->
                      <div class="symbol symbol-30px me-5">
                        <span class="symbol-label">
                          <i class="ki-duotone ki-magnifier fs-3 text-gray-600">
                            <!-- 아이콘 사진 넣는 곳 -->
                            <i class="fa-solid fa-bowl-food"></i>
                          </i>
                        </span>
                      </div>
                      <!--end::Symbol-->
                      <!--begin::Content-->
                      <div class="me-auto">
                        <!--begin::Title-->
                        <p style="color: black; font-size: 1rem">한식음식점</p>
                        <!--end::Desc-->
                      </div>
                      <!--end::Content-->
                    </div>
                    <!--end::Section-->
                    <!--begin::Wrapper-->
                    <div class="d-flex align-items-center">
                      <!--begin::Number-->
                      <span class="text-gray-800 fw-bold fs-6 me-3">124%</span>
                      <!--end::Number-->
                      <!--begin::Info-->
                      <div class="d-flex flex-center">
                        <!--begin::label-->
                        <span class="badge badge-light-success fs-base">
                          <i class="fa-solid fa-angle-up"></i> 4 점포
                        </span>
                        <!--end::label-->
                      </div>
                      <!--end::Info-->
                    </div>
                    <!--end::Wrapper-->
                  </div>
                  <!--end::Item-->
                  <!--begin::Separator-->
                  <hr />
                  <!--end::Separator-->
                  <!--begin::Item-->
                  <div class="d-flex flex-stack mt-3">
                    <!--begin::Section-->
                    <div
                      class="d-flex align-items-center me-5"
                      style="flex-grow: 1"
                    >
                      <!--begin::Symbol-->
                      <div class="symbol symbol-30px me-5">
                        <span class="symbol-label">
                          <i class="ki-duotone ki-magnifier fs-3 text-gray-600">
                            <!-- 아이콘 사진 넣는 곳 -->
                            <i class="fa-solid fa-bowl-food"></i>
                          </i>
                        </span>
                      </div>
                      <!--end::Symbol-->
                      <!--begin::Content-->
                      <div class="me-auto">
                        <!--begin::Title-->
                        <p style="color: black; font-size: 1rem">한식음식점</p>
                        <!--end::Desc-->
                      </div>
                      <!--end::Content-->
                    </div>
                    <!--end::Section-->
                    <!--begin::Wrapper-->
                    <div class="d-flex align-items-center">
                      <!--begin::Number-->
                      <span class="text-gray-800 fw-bold fs-6 me-3">124%</span>
                      <!--end::Number-->
                      <!--begin::Info-->
                      <div class="d-flex flex-center">
                        <!--begin::label-->
                        <span class="badge badge-light-success fs-base">
                          <i class="fa-solid fa-angle-up"></i> 4 점포
                        </span>
                        <!--end::label-->
                      </div>
                      <!--end::Info-->
                    </div>
                    <!--end::Wrapper-->
                  </div>
                  <!--end::Item-->
                </div>
                <!--end::Items-->
              </div>
              <!--end::Body-->
            </div>
            <!--end::List widget 7-->
          </div>
        </div>

        <!-- 최근 평균 소득이 높은 상권, 폐업률이 가장 높은 상권 -->
        <div
          class="row"
          style="display: flex; justify-content: center; align-items: center"
        >
          <!-- 최근 평균 소득이 높은 상권 -->
          <div class="col-xxl-4 mb-xxl-10">
            <!--begin::List widget 7-->
            <div class="card card-flush h-md-100">
              <!--begin::Header-->
              <div class="card-header py-7">
                <!--begin::Statistics-->
                <div class="m-0">
                  <!--begin::Heading-->
                  <div class="d-flex align-items-center mb-2">
                    <!--begin::Title-->
                    <span class="fs-2hx fw-bold text-gray-800 me-2 lh-1 ls-n2"
                      >최근 평균 소득이 높은 상권</span
                    >
                    <router-link
                      to="/infoPlaza/industry/TotalTrendingBusinessItems"
                      class="ms-auto"
                      style="font-size: 13px"
                    >
                      <i class="fa-solid fa-arrow-up-right-from-square"></i>
                      더보기
                    </router-link>
                    <!--end::Title-->
                  </div>
                  <!--end::Heading-->
                </div>
                <!--end::Statistics-->
                <!--begin::Toolbar-->
                <div class="card-toolbar"></div>
                <!--end::Toolbar-->
              </div>
              <!--end::Header-->
              <!--begin::Body-->
              <div class="card-body pt-0">
                <!--begin::Items-->
                <div class="mb-0">
                  <!--begin::Item-->
                  <div class="d-flex flex-stack mt-3">
                    <!--begin::Section-->
                    <div
                      class="d-flex align-items-center me-5"
                      style="flex-grow: 1"
                    >
                      <!--begin::Symbol-->
                      <div class="symbol symbol-30px me-5">
                        <span class="symbol-label">
                          <i class="ki-duotone ki-magnifier fs-3 text-gray-600">
                            <!-- 아이콘 사진 넣는 곳 -->
                            <i class="fa-solid fa-shop"></i>
                          </i>
                        </span>
                      </div>
                      <!--end::Symbol-->
                      <!--begin::Content-->
                      <div class="me-auto">
                        <!--begin::Title-->
                        <p style="color: gray; font-size: 0.6rem">발달상권</p>
                        <span style="color: black; font-size: 1rem"
                          >서대문역</span
                        >
                        <!--end::Desc-->
                      </div>
                      <!--end::Content-->
                    </div>
                    <!--end::Section-->
                    <!--begin::Wrapper-->
                    <div class="d-flex align-items-center">
                      <!--begin::Number-->
                      <span class="text-gray-800 fw-bold fs-6 me-3"
                        >₩ 3,219,553</span
                      >
                      <!--end::Number-->
                      <!--begin::Info-->
                      <div class="d-flex flex-center">
                        <!--begin::label-->
                        <span class="badge badge-light-success fs-base">
                          <i class="fa-solid fa-angle-up"></i> 10%
                        </span>
                        <!--end::label-->
                      </div>
                      <!--end::Info-->
                    </div>
                    <!--end::Wrapper-->
                  </div>
                  <!--end::Item-->
                  <!--begin::Separator-->
                  <hr />
                  <!--end::Separator-->

                  <div class="d-flex flex-stack mt-3">
                    <!--begin::Section-->
                    <div
                      class="d-flex align-items-center me-5"
                      style="flex-grow: 1"
                    >
                      <!--begin::Symbol-->
                      <div class="symbol symbol-30px me-5">
                        <span class="symbol-label">
                          <i class="ki-duotone ki-magnifier fs-3 text-gray-600">
                            <!-- 아이콘 사진 넣는 곳 -->
                            <i class="fa-solid fa-shop"></i>
                          </i>
                        </span>
                      </div>
                      <!--end::Symbol-->
                      <!--begin::Content-->
                      <div class="me-auto">
                        <!--begin::Title-->
                        <p style="color: gray; font-size: 0.6rem">발달상권</p>
                        <span style="color: black; font-size: 1rem"
                          >서대문역</span
                        >
                        <!--end::Desc-->
                      </div>
                      <!--end::Content-->
                    </div>
                    <!--end::Section-->
                    <!--begin::Wrapper-->
                    <div class="d-flex align-items-center">
                      <!--begin::Number-->
                      <span class="text-gray-800 fw-bold fs-6 me-3"
                        >₩ 3,219,553</span
                      >
                      <!--end::Number-->
                      <!--begin::Info-->
                      <div class="d-flex flex-center">
                        <!--begin::label-->
                        <span class="badge badge-light-success fs-base">
                          <i class="fa-solid fa-angle-up"></i> 10%
                        </span>
                        <!--end::label-->
                      </div>
                      <!--end::Info-->
                    </div>
                    <!--end::Wrapper-->
                  </div>
                  <!--end::Item-->
                  <!--begin::Separator-->
                  <hr />
                  <!--end::Separator-->

                  <div class="d-flex flex-stack mt-3">
                    <!--begin::Section-->
                    <div
                      class="d-flex align-items-center me-5"
                      style="flex-grow: 1"
                    >
                      <!--begin::Symbol-->
                      <div class="symbol symbol-30px me-5">
                        <span class="symbol-label">
                          <i class="ki-duotone ki-magnifier fs-3 text-gray-600">
                            <!-- 아이콘 사진 넣는 곳 -->
                            <i class="fa-solid fa-shop"></i>
                          </i>
                        </span>
                      </div>
                      <!--end::Symbol-->
                      <!--begin::Content-->
                      <div class="me-auto">
                        <!--begin::Title-->
                        <p style="color: gray; font-size: 0.6rem">발달상권</p>
                        <span style="color: black; font-size: 1rem"
                          >서대문역</span
                        >
                        <!--end::Desc-->
                      </div>
                      <!--end::Content-->
                    </div>
                    <!--end::Section-->
                    <!--begin::Wrapper-->
                    <div class="d-flex align-items-center">
                      <!--begin::Number-->
                      <span class="text-gray-800 fw-bold fs-6 me-3"
                        >₩ 3,219,553</span
                      >
                      <!--end::Number-->
                      <!--begin::Info-->
                      <div class="d-flex flex-center">
                        <!--begin::label-->
                        <span class="badge badge-light-success fs-base">
                          <i class="fa-solid fa-angle-up"></i> 10%
                        </span>
                        <!--end::label-->
                      </div>
                      <!--end::Info-->
                    </div>
                    <!--end::Wrapper-->
                  </div>
                  <!--end::Item-->
                  <!--begin::Separator-->
                  <hr />
                  <!--end::Separator-->

                  <div class="d-flex flex-stack mt-3">
                    <!--begin::Section-->
                    <div
                      class="d-flex align-items-center me-5"
                      style="flex-grow: 1"
                    >
                      <!--begin::Symbol-->
                      <div class="symbol symbol-30px me-5">
                        <span class="symbol-label">
                          <i class="ki-duotone ki-magnifier fs-3 text-gray-600">
                            <!-- 아이콘 사진 넣는 곳 -->
                            <i class="fa-solid fa-shop"></i>
                          </i>
                        </span>
                      </div>
                      <!--end::Symbol-->
                      <!--begin::Content-->
                      <div class="me-auto">
                        <!--begin::Title-->
                        <p style="color: gray; font-size: 0.6rem">발달상권</p>
                        <span style="color: black; font-size: 1rem"
                          >서대문역</span
                        >
                        <!--end::Desc-->
                      </div>
                      <!--end::Content-->
                    </div>
                    <!--end::Section-->
                    <!--begin::Wrapper-->
                    <div class="d-flex align-items-center">
                      <!--begin::Number-->
                      <span class="text-gray-800 fw-bold fs-6 me-3"
                        >₩ 3,219,553</span
                      >
                      <!--end::Number-->
                      <!--begin::Info-->
                      <div class="d-flex flex-center">
                        <!--begin::label-->
                        <span class="badge badge-light-success fs-base">
                          <i class="fa-solid fa-angle-up"></i> 10%
                        </span>
                        <!--end::label-->
                      </div>
                      <!--end::Info-->
                    </div>
                    <!--end::Wrapper-->
                  </div>
                  <!--end::Item-->
                  <!--begin::Separator-->
                  <hr />
                  <!--end::Separator-->

                  <div class="d-flex flex-stack mt-3">
                    <!--begin::Section-->
                    <div
                      class="d-flex align-items-center me-5"
                      style="flex-grow: 1"
                    >
                      <!--begin::Symbol-->
                      <div class="symbol symbol-30px me-5">
                        <span class="symbol-label">
                          <i class="ki-duotone ki-magnifier fs-3 text-gray-600">
                            <!-- 아이콘 사진 넣는 곳 -->
                            <i class="fa-solid fa-shop"></i>
                          </i>
                        </span>
                      </div>
                      <!--end::Symbol-->
                      <!--begin::Content-->
                      <div class="me-auto">
                        <!--begin::Title-->
                        <p style="color: gray; font-size: 0.6rem">발달상권</p>
                        <span style="color: black; font-size: 1rem"
                          >서대문역</span
                        >
                        <!--end::Desc-->
                      </div>
                      <!--end::Content-->
                    </div>
                    <!--end::Section-->
                    <!--begin::Wrapper-->
                    <div class="d-flex align-items-center">
                      <!--begin::Number-->
                      <span class="text-gray-800 fw-bold fs-6 me-3"
                        >₩ 3,219,553</span
                      >
                      <!--end::Number-->
                      <!--begin::Info-->
                      <div class="d-flex flex-center">
                        <!--begin::label-->
                        <span class="badge badge-light-success fs-base">
                          <i class="fa-solid fa-angle-up"></i> 10%
                        </span>
                        <!--end::label-->
                      </div>
                      <!--end::Info-->
                    </div>
                    <!--end::Wrapper-->
                  </div>
                  <!--end::Item-->
                </div>
                <!--end::Items-->
              </div>
              <!--end::Body-->
            </div>
            <!--end::List widget 7-->
          </div>

          <!-- 폐업률이 가장 높은 사업 아이템 -->
          <div class="col-xxl-4 mb-xxl-10">
            <!--begin::List widget 7-->
            <div class="card card-flush h-md-100">
              <!--begin::Header-->
              <div class="card-header py-7">
                <!--begin::Statistics-->
                <div class="m-0">
                  <!--begin::Heading-->
                  <div class="d-flex align-items-center mb-2">
                    <!--begin::Title-->
                    <span class="fs-2hx fw-bold text-gray-800 lh-1 ls-n2">
                      최근 폐업률이 높은 상권&사업 아이템
                    </span>
                    <router-link
                      to="/infoPlaza/industry/TotalTrendingBusinessItems"
                      class="ms-auto"
                      style="font-size: 13px"
                    >
                      <i class="fa-solid fa-arrow-up-right-from-square"></i>
                      더보기
                    </router-link>
                    <!--end::Title-->
                  </div>
                  <!--end::Heading-->
                </div>
                <!--end::Statistics-->
                <!--begin::Toolbar-->
                <div class="card-toolbar"></div>
                <!--end::Toolbar-->
              </div>
              <!--end::Header-->
              <!--begin::Body-->
              <div class="card-body pt-0">
                <!--begin::Items-->
                <div class="mb-0">
                  <!--begin::Item-->
                  <div class="d-flex flex-stack mt-3">
                    <!--begin::Section-->
                    <div
                      class="d-flex align-items-center me-5"
                      style="flex-grow: 1"
                    >
                      <!--begin::Symbol-->
                      <div class="symbol symbol-30px me-5">
                        <span class="symbol-label">
                          <i class="ki-duotone ki-magnifier fs-3 text-gray-600">
                            <!-- 아이콘 사진 넣는 곳 -->
                            <i class="fa-solid fa-bowl-food"></i>
                          </i>
                        </span>
                      </div>
                      <!--end::Symbol-->
                      <!--begin::Content-->
                      <div class="me-auto">
                        <!--begin::Title-->
                        <p style="color: gray; font-size: 0.6rem">서대문역</p>
                        <span style="color: black; font-size: 1rem"
                          >한식음식점</span
                        >
                        <!--end::Desc-->
                      </div>
                      <!--end::Content-->
                    </div>
                    <!--end::Section-->
                    <!--begin::Wrapper-->
                    <div class="d-flex align-items-center">
                      <!--begin::Number-->
                      <span class="text-gray-800 fw-bold fs-6 me-3">126</span>
                      <!--end::Number-->
                      <!--begin::Info-->
                      <div class="d-flex flex-center">
                        <!--begin::label-->
                        <span class="badge badge-light-danger fs-base">
                          <i class="fa-solid fa-angle-down"></i> 13%
                        </span>
                        <!--end::label-->
                      </div>
                      <!--end::Info-->
                    </div>
                    <!--end::Wrapper-->
                  </div>
                  <!--end::Item-->
                  <!--begin::Separator-->
                  <hr />
                  <!--end::Separator-->
                  <!--begin::Item-->
                  <div class="d-flex flex-stack mt-3">
                    <!--begin::Section-->
                    <div
                      class="d-flex align-items-center me-5"
                      style="flex-grow: 1"
                    >
                      <!--begin::Symbol-->
                      <div class="symbol symbol-30px me-5">
                        <span class="symbol-label">
                          <i class="ki-duotone ki-magnifier fs-3 text-gray-600">
                            <!-- 아이콘 사진 넣는 곳 -->
                            <i class="fa-solid fa-bowl-food"></i>
                          </i>
                        </span>
                      </div>
                      <!--end::Symbol-->
                      <!--begin::Content-->
                      <div class="me-auto">
                        <!--begin::Title-->
                        <p style="color: gray; font-size: 0.6rem">서대문역</p>
                        <span style="color: black; font-size: 1rem"
                          >한식음식점</span
                        >
                        <!--end::Desc-->
                      </div>
                      <!--end::Content-->
                    </div>
                    <!--end::Section-->
                    <!--begin::Wrapper-->
                    <div class="d-flex align-items-center">
                      <!--begin::Number-->
                      <span class="text-gray-800 fw-bold fs-6 me-3">126</span>
                      <!--end::Number-->
                      <!--begin::Info-->
                      <div class="d-flex flex-center">
                        <!--begin::label-->
                        <span class="badge badge-light-danger fs-base">
                          <i class="fa-solid fa-angle-down"></i> 13%
                        </span>
                        <!--end::label-->
                      </div>
                      <!--end::Info-->
                    </div>
                    <!--end::Wrapper-->
                  </div>
                  <!--end::Item-->
                  <!--begin::Separator-->
                  <hr />
                  <!--end::Separator-->
                  <!--begin::Item-->
                  <div class="d-flex flex-stack mt-3">
                    <!--begin::Section-->
                    <div
                      class="d-flex align-items-center me-5"
                      style="flex-grow: 1"
                    >
                      <!--begin::Symbol-->
                      <div class="symbol symbol-30px me-5">
                        <span class="symbol-label">
                          <i class="ki-duotone ki-magnifier fs-3 text-gray-600">
                            <!-- 아이콘 사진 넣는 곳 -->
                            <i class="fa-solid fa-bowl-food"></i>
                          </i>
                        </span>
                      </div>
                      <!--end::Symbol-->
                      <!--begin::Content-->
                      <div class="me-auto">
                        <!--begin::Title-->
                        <p style="color: gray; font-size: 0.6rem">서대문역</p>
                        <span style="color: black; font-size: 1rem"
                          >한식음식점</span
                        >
                        <!--end::Desc-->
                      </div>
                      <!--end::Content-->
                    </div>
                    <!--end::Section-->
                    <!--begin::Wrapper-->
                    <div class="d-flex align-items-center">
                      <!--begin::Number-->
                      <span class="text-gray-800 fw-bold fs-6 me-3">126</span>
                      <!--end::Number-->
                      <!--begin::Info-->
                      <div class="d-flex flex-center">
                        <!--begin::label-->
                        <span class="badge badge-light-danger fs-base">
                          <i class="fa-solid fa-angle-down"></i> 13%
                        </span>
                        <!--end::label-->
                      </div>
                      <!--end::Info-->
                    </div>
                    <!--end::Wrapper-->
                  </div>
                  <!--end::Item-->
                  <!--begin::Separator-->
                  <hr />
                  <!--end::Separator-->
                  <!--begin::Item-->
                  <div class="d-flex flex-stack mt-3">
                    <!--begin::Section-->
                    <div
                      class="d-flex align-items-center me-5"
                      style="flex-grow: 1"
                    >
                      <!--begin::Symbol-->
                      <div class="symbol symbol-30px me-5">
                        <span class="symbol-label">
                          <i class="ki-duotone ki-magnifier fs-3 text-gray-600">
                            <!-- 아이콘 사진 넣는 곳 -->
                            <i class="fa-solid fa-bowl-food"></i>
                          </i>
                        </span>
                      </div>
                      <!--end::Symbol-->
                      <!--begin::Content-->
                      <div class="me-auto">
                        <!--begin::Title-->
                        <p style="color: gray; font-size: 0.6rem">서대문역</p>
                        <span style="color: black; font-size: 1rem"
                          >한식음식점</span
                        >
                        <!--end::Desc-->
                      </div>
                      <!--end::Content-->
                    </div>
                    <!--end::Section-->
                    <!--begin::Wrapper-->
                    <div class="d-flex align-items-center">
                      <!--begin::Number-->
                      <span class="text-gray-800 fw-bold fs-6 me-3">126</span>
                      <!--end::Number-->
                      <!--begin::Info-->
                      <div class="d-flex flex-center">
                        <!--begin::label-->
                        <span class="badge badge-light-danger fs-base">
                          <i class="fa-solid fa-angle-down"></i> 13%
                        </span>
                        <!--end::label-->
                      </div>
                      <!--end::Info-->
                    </div>
                    <!--end::Wrapper-->
                  </div>
                  <!--end::Item-->
                  <!--begin::Separator-->
                  <hr />
                  <!--end::Separator-->
                  <!--begin::Item-->
                  <div class="d-flex flex-stack mt-3">
                    <!--begin::Section-->
                    <div
                      class="d-flex align-items-center me-5"
                      style="flex-grow: 1"
                    >
                      <!--begin::Symbol-->
                      <div class="symbol symbol-30px me-5">
                        <span class="symbol-label">
                          <i class="ki-duotone ki-magnifier fs-3 text-gray-600">
                            <!-- 아이콘 사진 넣는 곳 -->
                            <i class="fa-solid fa-bowl-food"></i>
                          </i>
                        </span>
                      </div>
                      <!--end::Symbol-->
                      <!--begin::Content-->
                      <div class="me-auto">
                        <!--begin::Title-->
                        <p style="color: gray; font-size: 0.6rem">서대문역</p>
                        <span style="color: black; font-size: 1rem"
                          >한식음식점</span
                        >
                        <!--end::Desc-->
                      </div>
                      <!--end::Content-->
                    </div>
                    <!--end::Section-->
                    <!--begin::Wrapper-->
                    <div class="d-flex align-items-center">
                      <!--begin::Number-->
                      <span class="text-gray-800 fw-bold fs-6 me-3">126</span>
                      <!--end::Number-->
                      <!--begin::Info-->
                      <div class="d-flex flex-center">
                        <!--begin::label-->
                        <span class="badge badge-light-danger fs-base">
                          <i class="fa-solid fa-angle-down"></i> 13%
                        </span>
                        <!--end::label-->
                      </div>
                      <!--end::Info-->
                    </div>
                    <!--end::Wrapper-->
                  </div>
                  <!--end::Item-->
                </div>
                <!--end::Items-->
              </div>
              <!--end::Body-->
            </div>
            <!--end::List widget 7-->
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
.badge-light-success {
  background-color: #d4edda !important; /* 밝은 녹색 배경색 */
  color: #155724 !important; /* 진한 녹색 텍스트 */
}
.badge-light-danger {
  background-color: rgba(220, 53, 69, 0.1); /* 연한 빨간색 배경 */
  color: #dc3545; /* 빨간색 텍스트 */
}
</style>
