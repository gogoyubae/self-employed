<template>
  <div>
    <InfoPlazaHeader />
    <div class="container mw-screen-xl">
      <div class="row justify-content-center">
        <div class="col-xl-3 col-md-6">
          <div
            class="card border-left-primary h-100 position-relative"
            style="border: 0"
          >
            <div
              class="card-body d-flex flex-column justify-content-center align-items-center"
            >
              <img
                src="@/assets/img/medals/leaf.png"
                style="max-width: 70%; height: auto"
                alt="..."
              />
              <div class="mt-5 d-flex flex-column text-overlay">
                <h1>BEST</h1>
                <h2>인기 업종</h2>
              </div>
            </div>
          </div>
        </div>

        <!-- 1등 카드 -->
        <div class="col-xl-3 col-md-6">
          <div class="card border-left-primary shadow h-100 py-2">
            <div
              class="card-body d-flex flex-column justify-content-center align-items-center"
            >
              <div class="text-center">
                <img
                  src="@/assets/img/medals/first_place_medal.png"
                  style="max-width: 60%; height: auto"
                  alt="..."
                />
              </div>
              <div
                class="row no-gutters align-items-center justify-content-center"
              >
                <div class="col text-center">
                  <div class="h3 mt-5 mb-2 font-weight-bold text-purple">
                    패션/뷰티
                  </div>
                  <div class="h4 mb-1 text-gray-300">
                    <h4>강남구 압구정동</h4>
                  </div>
                  <p>압구정로데오사거리</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- 2등, 3등 카드 -->
        <div class="col-xl-3 col-md-6 d-flex flex-column">
          <!-- 2등 카드 -->
          <div
            class="card border-left-primary shadow py-2 mb-2"
            style="flex: 1"
          >
            <div class="card-body d-flex align-items-center">
              <div class="text-left me-2">
                <img
                  src="@/assets/img/medals/second_place_medal.png"
                  style="max-width: 60px; height: auto"
                  alt="2nd place medal"
                />
              </div>
              <div class="ml-3">
                <div class="h4 font-weight-bold text-purple mb-1">유통</div>
                <div class="h6 text-gray-300">광진구 화양동</div>
                <p class="text-gray-300">세종대학교</p>
              </div>
            </div>
          </div>

          <!-- 3등 카드 -->
          <div class="card border-left-primary shadow py-2" style="flex: 1">
            <div class="card-body d-flex align-items-center">
              <div class="text-left me-2">
                <img
                  src="@/assets/img/medals/third_place_medal.png"
                  style="max-width: 60px; height: auto"
                  alt="3rd place medal"
                />
              </div>
              <div class="ml-3">
                <div class="h4 font-weight-bold text-purple mb-1">식음료</div>
                <div class="h6 text-gray-300">종로구 세운동</div>
                <p class="text-gray-300">세운상가</p>
              </div>
            </div>
          </div>
        </div>

        <!-- 필터링 카드 -->
        <div class="col-xl-3 col-md-6">
          <div class="card border-0 shadow h-100 py-4 text-center">
            <div
              class="card-body d-flex flex-column justify-content-center align-items-center"
            >
              <!-- 성별 필터링 -->
              <label
                for="genderFilter"
                class="fw-bold"
                style="font-size: 1.25rem"
                >성별</label
              >
              <div class="d-flex justify-content-center mt-2">
                <div class="form-check form-check-inline">
                  <input
                    type="checkbox"
                    class="form-check-input"
                    id="genderAll"
                  />
                  <label class="form-check-label" for="genderAll">전체</label>
                </div>
                <div class="form-check form-check-inline">
                  <input
                    type="checkbox"
                    class="form-check-input"
                    id="genderMale"
                  />
                  <label class="form-check-label" for="genderMale">남성</label>
                </div>
                <div class="form-check form-check-inline">
                  <input
                    type="checkbox"
                    class="form-check-input"
                    id="genderFemale"
                  />
                  <label class="form-check-label" for="genderFemale"
                    >여성</label
                  >
                </div>
              </div>

              <!-- 연령대 필터링 -->
              <label
                for="ageFilter"
                class="fw-bold mt-5"
                style="font-size: 1.25rem"
                >연령대</label
              >
              <div class="d-flex flex-wrap justify-content-center mt-2">
                <div class="form-check form-check-inline mb-2">
                  <input type="checkbox" class="form-check-input" id="ageAll" />
                  <label class="form-check-label" for="ageAll">전체</label>
                </div>
                <div class="form-check form-check-inline mb-2">
                  <input type="checkbox" class="form-check-input" id="age10" />
                  <label class="form-check-label" for="age10">10대</label>
                </div>
                <div class="form-check form-check-inline mb-2">
                  <input type="checkbox" class="form-check-input" id="age20" />
                  <label class="form-check-label" for="age20">20대</label>
                </div>
                <div class="form-check form-check-inline mb-2">
                  <input type="checkbox" class="form-check-input" id="age30" />
                  <label class="form-check-label" for="age30">30대</label>
                </div>
                <div class="form-check form-check-inline mb-2">
                  <input type="checkbox" class="form-check-input" id="age40" />
                  <label class="form-check-label" for="age40">40대</label>
                </div>
                <div class="form-check form-check-inline mb-2">
                  <input type="checkbox" class="form-check-input" id="age50" />
                  <label class="form-check-label" for="age50">50대</label>
                </div>
                <div class="form-check form-check-inline mb-2">
                  <input type="checkbox" class="form-check-input" id="age60" />
                  <label class="form-check-label" for="age60">60대 이상</label>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="row mt-20" style="display: flex; align-items: center">
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
                      Best 인기 업종 - 전체
                    </span>
                    <!--end::Title-->
                    <router-link
                      to="/infoPlaza/industry/totalTrendingBusinessItems"
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
                      Best 인기 업종 - My 위치
                    </span>
                    <router-link
                      to="/infoPlaza/industry/mylocationTrending"
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
                      최근 폐업률 순위
                    </span>
                    <router-link
                      to="/infoPlaza/industry/closeRatio"
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
.badge-light-success {
  background-color: #d4edda !important; /* 밝은 녹색 배경색 */
  color: #155724 !important; /* 진한 녹색 텍스트 */
}
.badge-light-danger {
  background-color: rgba(220, 53, 69, 0.1); /* 연한 빨간색 배경 */
  color: #dc3545; /* 빨간색 텍스트 */
}
.card {
  overflow: hidden; /* 카드가 내부 내용을 벗어나지 않도록 설정 */
  border-radius: 0.35rem; /* 카드의 모서리 라운드 설정 */
}

.text-overlay {
  /* position: absolute; */
  z-index: 1; /* 텍스트가 이미지 위에 표시되도록 설정 */
  text-align: left; /* 왼쪽 정렬 */
  font-weight: 600;
}
.text-purple {
  color: #fca3b9;
}
</style>
